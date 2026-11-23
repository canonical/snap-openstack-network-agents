# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import socket
import stat
from configparser import ConfigParser
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired
from unittest.mock import call, patch

import pytest
from sunbeam_ndr_contract import Agent

from openstack_network_agents.core.dynamic_routing import (
    DynamicRouting,
    parse_config,
)


def _apply(routing, raw):
    config = parse_config(raw)
    routing.apply(
        config.agents_for({item.agent.domain for item in config.placement}),
        transport=config.transport,
        ca_cert=config.ca_cert,
    )


def _instance(name, router_id="192.0.2.1", family="ipv4"):
    return {
        "domain": name,
        "family": family,
        "service-name": f"agent-{name}-v{family[-1]}",
        "host": f"agent-{name}-v{family[-1]}-node-01",
        "router-id": router_id,
        "peering": {"dedicated-uplink": {"interface": "test0"}},
    }


def _config(*agents, **settings):
    return json.dumps(
        {
            "instances": agents,
            "transport-url": "rabbit://neutron:secret@192.0.2.10:5672/openstack",
            **settings,
        }
    )


@pytest.mark.parametrize(
    "raw",
    [
        "{",
        {},
        False,
        _config(
            _instance("client"), **{"transport-url": "rabbit://invalid\n[DEFAULT]"}
        ),
        _config(_instance("client"), **{"ca-cert": "not a certificate"}),
        _config(_instance("../client")),
        _config(_instance("client"), _instance("public")),
        _config(_instance("client", family="ipv5")),
        _config(_instance("client"), _instance("client", "192.0.2.2", "ipv6")),
    ],
    ids=[
        "malformed",
        "object",
        "boolean",
        "newline",
        "invalid-ca",
        "path",
        "duplicate-router-id",
        "unknown-family",
        "duplicate-peered-domain",
    ],
)
def test_invalid_config_has_no_side_effects(tmp_path, raw):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with (
        patch("subprocess.run") as run,
        pytest.raises((TypeError, ValueError)) as error,
    ):
        _apply(routing, raw)

    assert "secret" not in str(error.value)
    run.assert_not_called()
    assert not routing.directory.exists()


def test_unconfigured_daemon_does_not_start(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with patch("subprocess.run") as run:
        _apply(routing, None)
        _apply(routing, _config())
        _apply(routing, {"instances": [_instance("client")]})

    run.assert_not_called()
    assert not routing.directory.exists()


def test_refresh_pauses_legacy_startup_without_touching_other_layers(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    routing.layer.parent.mkdir(parents=True)
    other = routing.layer.parent / "010-other.yaml"
    other.write_text("services: {}")
    routing.layer.write_text(
        json.dumps(
            {
                "services": {
                    "agent-red-v4": {"startup": "enabled", "command": "/agent"}
                },
                "log-targets": {"old-loki": {"type": "loki"}},
            }
        )
    )

    routing.guard_supervisor_start()

    assert other.read_text() == "services: {}"
    assert "log-targets" not in json.loads(routing.layer.read_text())
    assert json.loads(routing.layer.read_text())["services"] == {
        "agent-red-v4": {"startup": "disabled", "command": "/agent"}
    }


def test_peered_agents_only_start_through_host_reconciliation(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    instance = {
        **_instance("red"),
        "peering": {"dedicated-uplink": {"interface": "red0", "address": "192.0.2.3"}},
    }
    with patch("subprocess.run"):
        _apply(routing, _config(instance))

    service = json.loads(routing.layer.read_text())["services"]["agent-red-v4"]
    assert service["startup"] == "disabled"
    assert service["on-failure"] == "ignore"
    assert service["on-success"] == "ignore"


def test_tls_configuration_requires_hostname_capability(tmp_path):
    snap = tmp_path / "snap"
    routing = DynamicRouting(tmp_path, snap)
    driver = (
        snap / "usr/lib/python3/dist-packages/oslo_messaging/_drivers/impl_rabbit.py"
    )
    driver.parent.mkdir(parents=True)
    driver.write_text("ssl_ca_file")
    with pytest.raises(RuntimeError, match="cannot verify the broker hostname"):
        routing.verify_tls_support()

    driver.write_text(
        "cfg.BoolOpt('ssl_enforce_hostname_verification', default=False)\n"
        "def _fetch_ssl_params(self):\n"
        "    ssl_params = {}\n"
        "    ssl_params['server_hostname'] = self.ssl_server_hostname\n"
        "    return ssl_params\n"
    )
    routing.verify_tls_support()
    config = routing._render_agent(
        Agent("agent-red-v4", "net-01.red.v4", "198.18.0.1"), "rabbit://broker", True
    )
    assert "ssl_enforce_hostname_verification = true" in config
    assert f"ssl_ca_file = {routing.ca_file}" in config


@pytest.mark.parametrize("tls", [False, True])
def test_agent_config_uses_the_same_broker_options_in_both_tls_modes(tmp_path, tls):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    agent = Agent("agent-client6-v6", "net-01.client.v6", "198.18.0.1")
    transport = "rabbit://neutron:p%40ss%26word@broker"
    config = ConfigParser(interpolation=None)
    config.read_string(routing._render_agent(agent, transport, tls))

    assert config["DEFAULT"]["transport_url"] == transport
    assert config["DEFAULT"]["host"] == agent.host
    assert config["BGP"]["bgp_router_id"] == agent.router_id
    rabbit = config["oslo_messaging_rabbit"]
    assert rabbit.getboolean("ssl") is tls
    assert rabbit["ssl_ca_file"] == str(routing.ca_file)
    assert rabbit.getboolean("ssl_enforce_hostname_verification")


def test_agent_config_escapes_oslo_interpolation_in_transport_url(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    agent = Agent("agent-red-v4", "net-01.red.v4", "198.18.0.1")
    transport = "rabbit://user:p${password}@broker/$vhost%24"
    config = ConfigParser(interpolation=None)
    config.read_string(routing._render_agent(agent, transport, False))

    assert config["DEFAULT"]["transport_url"] == (
        "rabbit://user:p$${password}@broker/$$vhost%24"
    )


def test_agents_write_separate_rotating_logs_in_the_shared_slot(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with patch("subprocess.run"):
        _apply(routing, _config(_instance("alpha"), _instance("beta", "192.0.2.2")))

    assert routing.logs.is_dir()
    for name in ("agent-alpha-v4", "agent-beta-v4"):
        config = ConfigParser(interpolation=None)
        config.read(routing.directory / "agents" / name / "agent.conf")
        assert config["DEFAULT"]["log_file"] == str(routing.logs / f"{name}.log")
        assert config["DEFAULT"].getboolean("use_stderr")
        assert config["DEFAULT"]["log_rotation_type"] == "size"
        assert config["DEFAULT"].getint("max_logfile_size_mb") == 10
        assert config["DEFAULT"].getint("max_logfile_count") == 5


def test_placement_without_transport_stops_agents(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    instance = _instance("client")
    config = json.loads(_config(instance))

    with (
        patch("subprocess.run") as run,
        patch.object(routing, "_list_services", return_value={}),
        patch.object(routing, "_run_pebble", return_value=True) as pebble,
    ):
        _apply(routing, config)
        path = routing.directory / "agents" / "agent-client-v4" / "agent.conf"
        assert path.exists()

        (routing.pebble_dir / ".pebble.socket").touch()
        run.reset_mock()
        _apply(routing, {"instances": [instance]})
        assert call("stop", "agent-client-v4") in pebble.call_args_list
        run.assert_not_called()
        assert not path.exists()
        assert not routing.layer.exists()

        _apply(routing, config)
        assert call("start", "agent-client-v4") in pebble.call_args_list
        assert path.exists()


def test_reconcile_independent_agents_then_unset(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    alpha = _instance("alpha")
    beta = _instance("beta", "192.0.2.2")

    with (
        patch("subprocess.run") as run,
        patch.object(routing, "_list_services", return_value={}),
        patch.object(routing, "_run_pebble", return_value=True) as pebble,
    ):
        # snapctl can already have decoded the JSON object.
        _apply(routing, json.loads(_config(alpha)))
        assert run.call_args.args[0] == [
            "snapctl",
            "start",
            "--enable",
            "openstack-network-agents.pebble",
        ]
        alpha_file = routing.directory / "agents" / "agent-alpha-v4" / "agent.conf"
        assert stat.S_IMODE(alpha_file.stat().st_mode) == 0o600
        assert "host = agent-alpha-v4-node-01" in alpha_file.read_text()
        assert "bgp_router_id = 192.0.2.1" in alpha_file.read_text()
        assert "os_ken.driver.OsKenBgpDriver" in alpha_file.read_text()
        assert "rabbit_quorum_queue = true" in alpha_file.read_text()
        assert "secret" not in routing.layer.read_text()

        routing.socket.touch()
        run.reset_mock()
        pebble.reset_mock()
        _apply(routing, _config(alpha, beta))
        run.assert_not_called()
        assert not any(entry.args[0] == "stop" for entry in pebble.call_args_list)
        assert call("start", "agent-alpha-v4", "agent-beta-v4") in pebble.call_args_list
        assert set(json.loads(routing.layer.read_text())["services"]) == {
            "agent-alpha-v4",
            "agent-beta-v4",
        }

        pebble.reset_mock()
        _apply(routing, _config(beta))
        assert call("stop", "agent-alpha-v4") in pebble.call_args_list
        assert not alpha_file.exists()
        assert set(json.loads(routing.layer.read_text())["services"]) == {
            "agent-beta-v4"
        }

        _apply(routing, None)
        run.assert_not_called()
        assert not routing.layer.exists()
        assert not (
            routing.directory / "agents" / "agent-beta-v4" / "agent.conf"
        ).exists()


def test_apply_and_clear_only_the_ndr_layer_on_shared_pebble(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    other_layer = routing.layer.parent / "002-other.yaml"
    other_layer.parent.mkdir(parents=True)
    other_layer.write_text('{"services": {"other": {"command": "sleep 60"}}}')
    routing.socket.touch()
    updates = []

    def run_pebble(*args, **kwargs):
        if args[0] == "add":
            assert args[1:3] == ("--combine", "ndr")
            updates.append(
                json.loads(routing.directory.joinpath("update.yaml").read_text())
            )
        return True

    with (
        patch("subprocess.run") as snapctl,
        patch.object(routing, "_list_services", return_value={}),
        patch.object(routing, "_run_pebble", side_effect=run_pebble) as pebble,
    ):
        _apply(routing, _config(_instance("alpha")))
        _apply(routing, None)

    assert [
        entry.args for entry in pebble.call_args_list if entry.args[0] == "stop"
    ] == [("stop", "agent-alpha-v4")]
    assert [update["services"]["agent-alpha-v4"]["startup"] for update in updates] == [
        "disabled",
        "disabled",
    ]
    snapctl.assert_not_called()
    assert other_layer.exists()
    assert not routing.layer.exists()


def test_unreachable_pebble_does_not_block_clear_of_sole_layer(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with patch("subprocess.run") as snapctl:
        _apply(routing, _config(_instance("alpha")))
        (routing.pebble_dir / ".pebble.socket").touch()
        with patch.object(
            routing, "_list_services", side_effect=CalledProcessError(1, "pebble")
        ):
            _apply(routing, None)

    assert snapctl.call_args.args[0] == [
        "snapctl",
        "stop",
        "--disable",
        "openstack-network-agents.pebble",
    ]
    assert not routing.layer.exists()
    assert not list(routing.directory.rglob("agent.conf"))


def test_clear_retires_services_started_before_layer_was_saved(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with patch("subprocess.run") as run:
        _apply(routing, _config(_instance("alpha")))
        pending = routing.directory / "agents/agent-beta-v4/agent.conf"
        pending.parent.mkdir()
        pending.write_text("transport_url = rabbit://disposable")
        routing.socket.touch()
        run.return_value.stdout = json.dumps(
            {
                "services": {
                    name: {} for name in ("agent-alpha-v4", "agent-beta-v4", "other")
                }
            }
        )
        with patch.object(routing, "_run_pebble", return_value=True) as pebble:
            _apply(routing, None)

    assert call("stop", "agent-alpha-v4", "agent-beta-v4") in pebble.call_args_list
    assert not pending.exists()
    assert not routing.layer.exists()


def test_changing_config_restarts_only_affected_agent(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    alpha = _instance("alpha")
    beta = _instance("beta", "192.0.2.2")
    with (
        patch("subprocess.run"),
        patch.object(routing, "_list_services", return_value={}),
        patch.object(routing, "_run_pebble", return_value=True) as pebble,
    ):
        _apply(routing, _config(alpha, beta))
        routing.socket.touch()
        pebble.reset_mock()
        _apply(routing, _config(_instance("alpha", "192.0.2.3"), beta))

        assert [
            entry.args for entry in pebble.call_args_list if entry.args[0] == "stop"
        ] == [("stop", "agent-alpha-v4")]
        assert call("start", "agent-alpha-v4", "agent-beta-v4") in pebble.call_args_list


def test_dual_stack_reconciles_each_family_independently(tmp_path):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    ipv4 = _instance("client")
    ipv6 = _instance("client6", "192.0.2.2", "ipv6")

    with (
        patch("subprocess.run"),
        patch.object(routing, "_list_services", return_value={}),
        patch.object(routing, "_run_pebble", return_value=True) as pebble,
    ):
        _apply(routing, _config(ipv4))
        routing.socket.touch()
        pebble.reset_mock()

        _apply(routing, _config(ipv4, ipv6))
        assert not any(entry.args[0] == "stop" for entry in pebble.call_args_list)
        ipv6_config = routing.directory / "agents" / "agent-client6-v6" / "agent.conf"
        assert "host = agent-client6-v6-node-01" in ipv6_config.read_text()
        assert "bgp_router_id = 192.0.2.2" in ipv6_config.read_text()
        assert set(json.loads(routing.layer.read_text())["services"]) == {
            "agent-client-v4",
            "agent-client6-v6",
        }

        pebble.reset_mock()
        _apply(routing, _config(ipv4))
        assert [
            entry.args for entry in pebble.call_args_list if entry.args[0] == "stop"
        ] == [("stop", "agent-client6-v6")]
        assert not ipv6_config.exists()


@pytest.fixture
def routing_with_socket(tmp_path, monkeypatch):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    routing.pebble_dir.mkdir()
    monkeypatch.chdir(routing.pebble_dir)
    # Linux limits UNIX socket addresses to 107 bytes.
    routing.socket = Path(".pebble.socket")
    return routing


def test_recover_active_placement_with_abandoned_pebble_socket(routing_with_socket):
    routing = routing_with_socket
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(routing.socket))

    with (
        patch.object(
            routing, "_list_services", side_effect=CalledProcessError(1, "pebble")
        ),
        patch("subprocess.run") as snapctl,
    ):
        _apply(routing, _config(_instance("alpha")))

    snapctl.assert_called_once_with(
        ["snapctl", "start", "--enable", "openstack-network-agents.pebble"],
        check=True,
        timeout=35,
    )
    assert routing.socket.is_socket()


def test_keeps_socket_when_live_pebble_cannot_list_services(routing_with_socket):
    routing = routing_with_socket
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(routing.socket))
        listener.listen()
        with (
            patch.object(
                routing, "_list_services", side_effect=CalledProcessError(1, "pebble")
            ),
            patch("subprocess.run") as snapctl,
            pytest.raises(RuntimeError, match="supervisor is unreachable"),
        ):
            _apply(routing, _config(_instance("alpha")))
    snapctl.assert_not_called()
    assert routing.socket.is_socket()


def test_pebble_timeout_is_not_a_stale_socket(routing_with_socket):
    routing = routing_with_socket
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(routing.socket))
    with (
        patch.object(
            routing, "_list_services", side_effect=TimeoutExpired("pebble", 35)
        ),
        patch("subprocess.run") as snapctl,
        pytest.raises(RuntimeError, match="supervisor is unreachable"),
    ):
        _apply(routing, _config(_instance("alpha")))
    snapctl.assert_not_called()
    assert routing.socket.is_socket()


@pytest.mark.parametrize("bad_layer", ['{"services":', '{"services": []}'])
@pytest.mark.parametrize("startup_first", [False, True])
def test_quarantines_only_corrupt_ndr_layer_and_rebuilds(
    tmp_path, bad_layer, startup_first
):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    routing.layer.parent.mkdir(parents=True)
    routing.layer.write_text(bad_layer)
    other = routing.layer.parent / "010-other.yaml"
    other.write_text("services: {}")

    if startup_first:
        routing.guard_supervisor_start()
        assert not routing.layer.exists()

    with patch("subprocess.run"):
        _apply(routing, _config(_instance("alpha")))

    assert other.read_text() == "services: {}"
    assert routing.layer.with_suffix(".invalid").read_text() == bad_layer
    services = json.loads(routing.layer.read_text())["services"]
    assert services["agent-alpha-v4"]["startup"] == "disabled"


@pytest.mark.parametrize("other_service", [False, True])
def test_disable_stops_sole_supervisor_but_preserves_unrelated_live_services(
    tmp_path, other_service
):
    routing = DynamicRouting(tmp_path, tmp_path / "snap")
    with patch("subprocess.run"):
        _apply(routing, _config(_instance("alpha")))
    routing.socket.touch()
    live = {"agent-alpha-v4": {"current": "active"}}
    if other_service:
        live["other"] = {"current": "active"}
    with (
        patch.object(routing, "_list_services", return_value=live),
        patch.object(routing, "_run_pebble") as pebble,
        patch.object(routing, "_stop_supervisor") as stop,
    ):
        routing.apply([], disable_supervisor=True)

    if other_service:
        stop.assert_not_called()
        assert call("stop", "agent-alpha-v4") in pebble.call_args_list
    else:
        stop.assert_called_once_with()
        pebble.assert_not_called()
    assert not routing.layer.exists()
