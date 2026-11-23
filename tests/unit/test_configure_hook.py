# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from openstack_network_agents.hooks import configure


@pytest.mark.parametrize(
    "change, expect_ovn",
    [
        ("enable", False),
        ("unset", False),
        ("mixed", True),
        ("no-op", True),
        ("refresh", True),
        ("connect", True),
    ],
)
def test_configure_ovn_only_skipped_for_ndr_only_updates(tmp_path, change, expect_ovn):
    snap = Mock(
        paths=SimpleNamespace(common=tmp_path, data=tmp_path, snap=tmp_path / "1")
    )
    snap.config.get_options.return_value.as_dict.side_effect = lambda: dict(options)
    ndr_config = '{"instances": []}'
    initial_ndr = ndr_config if change == "unset" else None
    options = {
        "network": {"bridge-mapping": "physnet1:br-ex"},
        "ndr": {"config": initial_ndr},
    }
    snap.config.get_options.return_value.get.return_value = initial_ndr

    with (
        patch.object(configure, "setup_logging"),
        patch.object(configure, "update_default_config"),
        patch.object(
            configure, "is_connected", side_effect=[change != "connect", True]
        ),
        patch.object(configure, "_configure_ovn_external_networking") as ovn,
        patch.object(configure, "NDRHost") as routing,
    ):
        configure.hook(snap)
        ovn.reset_mock()

        next_ndr = None if change in ("no-op", "unset") else ndr_config
        options["ndr"] = {"config": next_ndr}
        snap.config.get_options.return_value.get.return_value = next_ndr
        if change == "mixed":
            options["network"]["bridge-mapping"] = "physnet1:br-provider"
        if change == "refresh":
            snap.paths.snap = tmp_path / "2"
        configure.hook(snap)

    assert ovn.call_args_list == ([call(snap)] if expect_ovn else [])
    assert routing.return_value.validate_pending_config.call_args_list == [
        call(initial_ndr),
        call(next_ndr),
    ]


@pytest.mark.parametrize(
    "ovn_connected", [True, False], ids=["connected", "disconnected"]
)
def test_configure_schedules_dynamic_routing_once(tmp_path, ovn_connected):
    snap = Mock(
        paths=SimpleNamespace(common=tmp_path, data=tmp_path, snap=tmp_path / "snap")
    )
    ndr_config = '{"instances": []}'
    snap.config.get_options.return_value.as_dict.return_value = {"ndr": ndr_config}
    snap.config.get_options.return_value.get.return_value = ndr_config
    lifecycle = Mock()

    with (
        patch.object(configure, "setup_logging"),
        patch.object(configure, "update_default_config", lifecycle.set_defaults),
        patch.object(
            configure, "is_connected", return_value=ovn_connected
        ) as connected,
        patch.object(
            configure, "_configure_ovn_external_networking", lifecycle.configure_ovn
        ),
        patch.object(configure, "NDRHost") as routing,
    ):
        routing.return_value.validate_pending_config = lifecycle.validate_ndr
        routing.return_value.schedule_reconcile = lifecycle.schedule_ndr

        configure.hook(snap)

    connected.assert_called_once_with(configure.OVN_CHASSIS_PLUG)
    snap.config.get_options.assert_called_once_with("network", "logging", "ndr")
    snap.config.get_options.return_value.get.assert_called_once_with("ndr.config")
    routing.assert_called_once_with(snap)
    expected_calls = [call.set_defaults(snap), call.validate_ndr(ndr_config)]
    if ovn_connected:
        expected_calls.append(call.configure_ovn(snap))
    expected_calls.append(call.schedule_ndr(lifecycle.validate_ndr.return_value))
    assert lifecycle.mock_calls == expected_calls


def test_invalid_ndr_in_mixed_update_does_not_change_ovn(tmp_path):
    snap = Mock(
        paths=SimpleNamespace(common=tmp_path, data=tmp_path, snap=tmp_path / "snap")
    )
    options = snap.config.get_options.return_value
    ndr_config = {
        "instances": [
            {
                "domain": "red",
                "family": "ipv4",
                "service-name": "agent-red",
                "host": "net-01.red",
                "router-id": "198.18.0.1",
                "peering": {
                    "provider-trunk": {
                        "physnet": "physnet1",
                        "vlan": 4095,
                        "address": "192.0.2.3/28",
                    },
                },
            },
        ],
        "transport-url": "rabbit://broker",
    }
    options.as_dict.return_value = {
        "network": {"bridge-mapping": "physnet1:br-provider"},
        "ndr": {"config": ndr_config},
    }
    options.get.return_value = ndr_config

    with (
        patch.object(configure, "setup_logging"),
        patch.object(configure, "update_default_config"),
        patch.object(configure, "is_connected", return_value=True),
        patch.object(configure, "_configure_ovn_external_networking") as ovn,
        patch("openstack_network_agents.core.ndr_host.subprocess.run") as snapctl,
        pytest.raises(ValueError, match="Invalid NDR physnet or peering VLAN"),
    ):
        configure.hook(snap)

    ovn.assert_not_called()
    snapctl.assert_not_called()
    assert not (tmp_path / "configure-state").exists()
