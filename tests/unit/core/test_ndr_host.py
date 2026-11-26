# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import socket
from subprocess import CalledProcessError, TimeoutExpired
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
from sunbeam_ndr_contract import Agent

from openstack_network_agents.core import ndr_host, ndr_peering
from openstack_network_agents.core.dynamic_routing import DynamicRouting
from openstack_network_agents.core.ndr_host import HostState


@pytest.fixture
def host(tmp_path, monkeypatch):
    snap = Mock(paths=SimpleNamespace(common=tmp_path, snap=tmp_path))
    host = ndr_host.NDRHost(snap)
    host.routing = Mock()
    peer = Mock()
    peer.resolve.side_effect = lambda instances, **kwargs: (
        [item.agent.domain for item in instances],
        instances,
    )
    peer.firewall_fingerprint.return_value = "observed"
    peer.firewall_batch.side_effect = str
    peer.ready.return_value = {"red"}
    peer.managed_ports_match.return_value = True
    monkeypatch.setattr(ndr_host, "_host", lambda snap: peer)
    return host, peer


def _committed_config(host, payload):
    host.snap.config.get_options.return_value.get.side_effect = {
        "ndr.config": payload,
    }.get


def _apply(host, payload, *, polling=False):
    _committed_config(host, payload)
    return host.reconcile(polling=polling)


@pytest.fixture
def instance():
    return {
        "domain": "red",
        "family": "ipv4",
        "service-name": "agent-red-v4",
        "host": "net-01.red.v4",
        "router-id": "198.18.0.1",
        "peering": {
            "provider-trunk": {
                "physnet": "physnet1",
                "vlan": 120,
                "address": "192.0.2.3/28",
            }
        },
    }


def test_legacy_identity_is_not_activated(host, instance):
    host, peer = host
    instance.pop("peering")
    payload = {"instances": [instance], "transport-url": "rabbit://broker"}

    assert _apply(host, payload) is HostState.WAITING_FOR_PLACEMENT

    host.routing.apply.assert_called_once_with([])
    peer.apply.assert_not_called()
    assert payload["instances"] == [instance]


def test_legacy_identity_cannot_share_a_protected_domain(host, instance):
    host, _ = host
    legacy = {key: value for key, value in instance.items() if key != "peering"}
    legacy.update(
        {"service-name": "legacy-red", "host": "legacy.red", "router-id": "198.18.0.2"}
    )
    payload = {"instances": [legacy, instance], "transport-url": "rabbit://broker"}

    assert _apply(host, payload) is HostState.WAITING_FOR_PEERINGS

    agents = host.routing.apply.call_args.args[0]
    assert [agent.service for agent in agents] == ["agent-red-v4"]


def test_amqp_loss_preserves_host_resources(host, instance):
    host, peer = host
    payload = {"instances": [], "paused-instances": [instance]}

    assert _apply(host, payload) is HostState.PAUSED

    peer.apply.assert_called_once_with(["red"], rewrite_firewall=True)
    host.routing.stop_unwanted.assert_not_called()
    host.routing.apply.assert_called_once_with([])


@pytest.mark.parametrize("paused", [True, False], ids=["paused", "waiting-for-address"])
def test_watcher_recreates_managed_port_without_an_active_agent(
    host, instance, monkeypatch, paused
):
    host, _ = host
    interface = "ndr-b1f51a511f1"
    metadata = {
        "sunbeam-ndr-domain": "red",
        "sunbeam-ndr-bridge": "br-ex",
        "sunbeam-ndr-vlan": "120",
        "sunbeam-ndr-address": "192.0.2.3/28",
    }
    ports = {}
    links = {}
    ovs = Mock()
    ovs.get_bridge_physnet_map.return_value = {"br-ex": "physnet1"}
    ovs.list_bridge_interfaces.return_value = ["br-ex", "eno2"]
    ovs.list_table.side_effect = lambda table, name, fields: ports.get(
        (table, name), {}
    )
    ovs.find.side_effect = lambda *_: {
        "headings": ["name", "external_ids"],
        "data": [[interface, ["map", list(metadata.items())]]]
        if ("Port", interface) in ports
        else [],
    }

    def vsctl(command, *args, **kwargs):
        if command == "port-to-br":
            return "br-ex"
        assert command == "add-port"
        ports["Port", interface] = {
            "external_ids": metadata,
            "tag": 120,
            "vlan_mode": "access",
            "trunks": [],
        }
        ports["Interface", interface] = {"type": "internal"}

    ovs.vsctl.side_effect = vsctl
    monkeypatch.setattr(ndr_peering, "_links", lambda: links)
    monkeypatch.setattr(ndr_host, "_host", lambda snap: ndr_peering.NDRPeering(ovs))
    monkeypatch.setattr(ndr_peering.subprocess, "run", Mock())
    monkeypatch.setattr(
        ndr_peering.NDRPeering, "firewall_fingerprint", lambda self: "live"
    )
    host.routing.services_started.return_value = True
    if paused:
        payload = {"instances": [], "paused-instances": [instance]}
    else:
        payload = {"instances": [instance], "transport-url": "rabbit://broker"}

    assert _apply(host, payload, polling=True) is HostState.WAITING_FOR_PEERINGS
    assert ("Port", interface) in ports
    if paused:
        links[interface] = {
            "flags": ["UP"],
            "addr_info": [{"local": "192.0.2.3", "prefixlen": 28, "scope": "global"}],
        }
        assert _apply(host, payload, polling=True) is HostState.PAUSED

    ports.clear()
    links.clear()
    ovs.vsctl.reset_mock()

    assert _apply(host, payload, polling=True) is HostState.WAITING_FOR_PEERINGS
    assert ovs.vsctl.call_args.args[:3] == ("add-port", "br-ex", interface)
    assert ("Port", interface) in ports
    assert host.routing.apply.call_args.args[0] == []


def test_pending_config_has_no_host_side_effects_before_commit(
    host, instance, monkeypatch
):
    host, peer = host
    queue = Mock()
    monkeypatch.setattr(ndr_host.subprocess, "run", queue)
    pending = {"instances": [instance], "transport-url": "rabbit://broker"}
    _committed_config(host, {"instances": []})

    host.schedule_reconcile(host.validate_pending_config(pending))

    queue.assert_called_once_with(
        ["snapctl", "start", "--enable", "openstack-network-agents.ndr-host"],
        check=True,
        timeout=35,
    )
    peer.apply.assert_not_called()
    host.routing.apply.assert_not_called()
    assert not host.firewall_state.exists()

    # snapd rejected the update, so the watcher still sees the old config.
    assert host.reconcile(polling=True) is HostState.DISABLED
    assert not host.firewall_state.exists()

    # A later successful update can be reconciled without a stale generation.
    assert _apply(host, pending, polling=True) is HostState.READY
    assert host.firewall_state.exists()


def test_rule_drift_is_repaired_before_agents_start(host, instance):
    host, peer = host
    payload = {"instances": [instance], "transport-url": "rabbit://broker"}
    assert _apply(host, payload) is HostState.READY
    agents = host.routing.apply.call_args.args[0]
    timeline = Mock()
    peer.apply = timeline.firewall
    host.routing.stop_unwanted = timeline.stop_unwanted
    host.routing.apply = timeline.apply
    peer.firewall_fingerprint.side_effect = ["tampered", "repaired"]

    assert _apply(host, payload, polling=True) is HostState.READY

    assert timeline.mock_calls == [
        call.stop_unwanted(set()),
        call.firewall(["red"], rewrite_firewall=True),
        call.apply(agents, transport="rabbit://broker", ca_cert=""),
    ]


def test_watcher_rechecks_protection_before_starting_an_exited_agent(host, instance):
    host, peer = host
    payload = {"instances": [instance], "transport-url": "rabbit://broker"}
    assert _apply(host, payload) is HostState.READY
    agents = host.routing.apply.call_args.args[0]
    timeline = Mock()
    peer.firewall_fingerprint = timeline.firewall
    timeline.firewall.return_value = "observed"
    peer.ready = timeline.ready
    timeline.ready.return_value = {"red"}
    host.routing.services_started = timeline.running
    timeline.running.return_value = False
    host.routing.apply = timeline.apply

    assert _apply(host, payload, polling=True) is HostState.READY

    assert timeline.mock_calls == [
        call.firewall(),
        call.ready(["red"], verify_ports=True),
        call.running({"agent-red-v4"}),
        call.ready(["red"]),
        call.apply(agents, transport="rabbit://broker", ca_cert=""),
    ]


def test_adding_attachment_preserves_ready_peer(host, instance):
    host, _ = host
    payload = {"instances": [instance], "transport-url": "rabbit://broker"}
    assert _apply(host, payload) is HostState.READY
    new = {
        **instance,
        "domain": "blue",
        "service-name": "agent-blue-v4",
        "host": "net-01.blue.v4",
        "router-id": "198.18.0.2",
    }
    agents = host.routing.apply.call_args.args[0]
    host.routing.stop_unwanted.reset_mock()

    assert (
        _apply(host, {**payload, "instances": [instance, new]})
        is HostState.WAITING_FOR_PEERINGS
    )

    host.routing.stop_unwanted.assert_called_once_with({"agent-red-v4"})
    host.routing.apply.assert_called_with(
        agents, transport="rabbit://broker", ca_cert=""
    )


@pytest.mark.parametrize("lost", ["interface", "address"])
def test_watcher_keeps_other_domain_when_dedicated_uplink_is_unavailable(
    host, instance, monkeypatch, lost
):
    host, _ = host
    red = {
        **instance,
        "peering": {"dedicated-uplink": {"interface": "red0", "address": "192.0.2.3"}},
    }
    blue = {
        **instance,
        "domain": "blue",
        "service-name": "agent-blue-v4",
        "host": "net-01.blue.v4",
        "router-id": "198.18.0.2",
        "peering": {
            "dedicated-uplink": {"interface": "blue0", "address": "198.51.100.3"}
        },
    }
    links = {
        "red0": {
            "flags": ["UP"],
            "addr_info": [{"local": "192.0.2.3", "prefixlen": 28, "scope": "global"}],
        },
        "blue0": {
            "flags": ["UP"],
            "addr_info": [
                {"local": "198.51.100.3", "prefixlen": 28, "scope": "global"}
            ],
        },
    }
    ovs = Mock()
    ovs.get_bridge_physnet_map.return_value = {}
    ovs.find.return_value = {"headings": [], "data": []}
    apply = Mock()
    monkeypatch.setattr(ndr_peering, "_links", lambda: links)
    monkeypatch.setattr(ndr_host, "_host", lambda snap: ndr_peering.NDRPeering(ovs))
    monkeypatch.setattr(ndr_peering.NDRPeering, "apply", apply)
    monkeypatch.setattr(
        ndr_peering.NDRPeering, "firewall_fingerprint", lambda self: "live"
    )
    payload = {"instances": [red, blue], "transport-url": "rabbit://broker"}

    assert _apply(host, payload) is HostState.READY
    agents = host.routing.apply.call_args.args[0]
    blue_link = links["blue0"]
    if lost == "interface":
        del links["blue0"]
    else:
        links["blue0"] = {"flags": ["UP"], "addr_info": []}
    host.routing.reset_mock()
    apply.reset_mock()

    with pytest.raises(ValueError, match="NDR dedicated interface blue0"):
        ndr_host.validate(host.snap, payload["instances"])
    host.routing.stop_unwanted.assert_not_called()
    assert _apply(host, payload, polling=True) is HostState.WAITING_FOR_PEERINGS
    host.routing.stop_unwanted.assert_called_once_with({"agent-red-v4"})
    host.routing.apply.assert_called_once_with(
        [Agent("agent-red-v4", "net-01.red.v4", "198.18.0.1", "red")],
        transport="rabbit://broker",
        ca_cert="",
    )
    attachments = apply.call_args.args[0]
    assert [item.interface for item in attachments] == ["red0", "blue0"]
    assert not apply.call_args.kwargs["rewrite_firewall"]

    links["blue0"] = blue_link
    assert _apply(host, payload, polling=True) is HostState.READY
    host.routing.apply.assert_called_with(
        agents, transport="rabbit://broker", ca_cert=""
    )


def test_physnet_drift_stops_agents_and_retains_existing_protection(host, instance):
    host, peer = host
    payload = {"instances": [instance], "transport-url": "rabbit://broker"}
    assert _apply(host, payload) is HostState.READY
    previous_firewall = host.firewall_state.read_text()
    host.routing.reset_mock()
    peer.apply.reset_mock()
    peer.resolve.side_effect = ValueError(
        "NDR physnet must resolve to one local bridge."
    )

    with pytest.raises(ValueError, match="physnet must resolve"):
        _apply(host, payload, polling=True)

    host.routing.apply.assert_called_once_with([])
    peer.apply.assert_not_called()
    assert host.firewall_state.read_text() == previous_firewall


def test_explicit_clear_stops_agents_before_removing_host_resources(host, instance):
    host, peer = host
    assert (
        _apply(host, {"instances": [instance], "transport-url": "rabbit://broker"})
        is HostState.READY
    )
    timeline = Mock()
    peer.ready.return_value = set()
    peer.apply = timeline.firewall
    host.routing.stop_unwanted = timeline.stop_unwanted
    host.routing.apply = timeline.apply

    assert _apply(host, {"instances": []}) is HostState.DISABLED

    assert timeline.mock_calls == [
        call.apply([], disable_supervisor=True),
        call.firewall([], rewrite_firewall=True),
    ]
    assert not host.firewall_state.exists()


@pytest.mark.parametrize("supervisor", ["sole", "shared", "stop-failed"])
def test_disable_with_unreachable_pebble_supervisor(host, monkeypatch, supervisor):
    host, peer = host
    root = host.snap.paths.common
    host.routing = DynamicRouting(root, root)
    host.firewall_state.parent.mkdir(parents=True)
    host.firewall_state.write_text("old-intent\nobserved")
    host.routing.layer.parent.mkdir(parents=True)
    host.routing.layer.write_text(
        json.dumps({"services": {"agent-red": {"command": "/bin/sleep 60"}}})
    )
    if supervisor == "shared":
        host.routing.layer.with_name("002-other.yaml").write_text("services: {}")
    monkeypatch.chdir(host.routing.pebble_dir)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(".pebble.socket")
    failure = (
        TimeoutExpired("pebble", 35)
        if supervisor == "shared"
        else CalledProcessError(1, ["pebble", "services", "--format=json"])
    )
    monkeypatch.setattr(host.routing, "_list_services", Mock(side_effect=failure))
    timeline = Mock()
    monkeypatch.setattr(ndr_host.subprocess, "run", timeline.snapctl)
    peer.apply = timeline.firewall
    peer.ready.return_value = set()
    _committed_config(host, {"instances": []})

    if supervisor == "shared":
        with pytest.raises(RuntimeError, match="Pebble supervisor is unreachable"):
            host.reconcile()
        timeline.snapctl.assert_not_called()
    elif supervisor == "stop-failed":
        timeline.snapctl.side_effect = CalledProcessError(1, ["snapctl", "stop"])
        with pytest.raises(CalledProcessError):
            host.reconcile()
        timeline.snapctl.assert_called_once()
    if supervisor != "sole":
        timeline.firewall.assert_not_called()
        assert host.routing.socket.is_socket()
        assert host.routing.layer.exists()
        assert host.firewall_state.exists()
        return

    assert host.reconcile() is HostState.DISABLED
    assert timeline.mock_calls == [
        call.snapctl(
            ["snapctl", "stop", "--disable", "openstack-network-agents.pebble"],
            check=True,
            timeout=35,
        ),
        call.firewall([], rewrite_firewall=True),
    ]
    assert not (host.routing.pebble_dir / ".pebble.socket").exists()
    assert not host.routing.layer.exists()
    assert not host.firewall_state.exists()


def test_uninstall_cleans_owned_host_state_after_services_stop(host):
    host, peer = host
    host.firewall_state.parent.mkdir(parents=True)
    host.firewall_state.touch()

    host.cleanup_after_stop()

    peer.apply.assert_called_once_with([], rewrite_firewall=True)
    host.snap.config.get_options.assert_not_called()
    host.routing.apply.assert_not_called()
    assert not host.firewall_state.exists()

    peer.reset_mock()
    host.cleanup_after_stop()
    peer.apply.assert_not_called()


def test_uninstall_retains_state_if_ovs_cleanup_fails(host):
    host, peer = host
    host.firewall_state.parent.mkdir(parents=True)
    host.firewall_state.touch()
    peer.apply.side_effect = RuntimeError("OVSDB unavailable")

    with pytest.raises(RuntimeError, match="OVSDB unavailable"):
        host.cleanup_after_stop()

    assert host.firewall_state.exists()
