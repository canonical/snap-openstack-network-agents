# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from ipaddress import ip_interface
from unittest.mock import Mock

import pytest
from sunbeam_ndr_contract import parse_instances

from openstack_network_agents.core import ndr_peering


def _instance(domain, mode, family, **peering):
    return parse_instances(
        [
            {
                "domain": domain,
                "family": family,
                "host": domain,
                "service-name": "agent-" + domain,
                "router-id": "192.0.2.1",
                "peering": {mode: peering},
            }
        ]
    )[0]


@pytest.fixture
def host(monkeypatch):
    links = {
        "eno1": {},
        "uplink122": {
            "flags": ["UP"],
            "link": "eno1",
            "linkinfo": {"info_kind": "vlan"},
            "addr_info": [{"local": "2001:db8::3", "prefixlen": 64, "scope": "global"}],
        },
    }
    ovs = Mock()
    ovs.get_bridge_physnet_map.return_value = {"br-ex": "physnet1"}
    ovs.list_bridge_interfaces.return_value = ["br-ex", "eno2"]
    ovs.list_table.return_value = {}
    ovs.find.return_value = {"headings": [], "data": []}
    monkeypatch.setattr(ndr_peering, "_links", lambda: links)
    return ndr_peering.NDRPeering(ovs)


def test_resolve_managed_and_dedicated_attachments(host):
    instances = [
        _instance(
            "red",
            "provider-trunk",
            "ipv4",
            physnet="physnet1",
            vlan=120,
            address="192.0.2.3/28",
        ),
        _instance("blue", "dedicated-uplink", "ipv6", interface="uplink122"),
    ]
    attachments, normalized = host.resolve(instances)
    red, blue = attachments
    assert red.bridge == "br-ex"
    assert red.vlan == 120
    assert len(red.interface) <= 15
    assert blue.interface == "uplink122"
    assert normalized[0] == instances[0].declaration
    assert normalized[1]["peering"]["dedicated-uplink"]["address"] == "2001:db8::3"


def test_reject_shared_provider_segment(host):
    instances = [
        _instance(
            "red",
            "provider-trunk",
            "ipv4",
            physnet="physnet1",
            vlan=120,
            address="192.0.2.3/28",
        ),
        _instance(
            "blue",
            "provider-trunk",
            "ipv6",
            physnet="physnet1",
            vlan=120,
            address="2001:db8::4/64",
        ),
    ]
    with pytest.raises(ValueError, match="bridge and VLAN pair must be exclusive"):
        host.resolve(instances)


def test_reject_managed_port_ownership_conflict(host):
    host.ovs.list_table.return_value = {"external_ids": {"operator": "yes"}, "tag": 120}
    with pytest.raises(ValueError, match="Conflicting NDR peering interface"):
        host.resolve(
            [
                _instance(
                    "red",
                    "provider-trunk",
                    "ipv4",
                    physnet="physnet1",
                    vlan=120,
                    address="192.0.2.3/28",
                )
            ]
        )
    host.ovs.del_port.assert_not_called()


@pytest.mark.parametrize(
    ("vlan_mode", "trunks", "valid"),
    [
        ([], [], True),
        ("access", [], True),
        ("native-tagged", [121], False),
        ("trunk", [], False),
        ("access", [121], False),
    ],
)
def test_managed_port_requires_an_access_vlan(host, vlan_mode, trunks, valid):
    declaration = _instance(
        "red",
        "provider-trunk",
        "ipv4",
        physnet="physnet1",
        vlan=120,
        address="192.0.2.3/28",
    )
    host.ovs.list_table.side_effect = [
        {
            "external_ids": {
                "sunbeam-ndr-domain": "red",
                "sunbeam-ndr-bridge": "br-ex",
                "sunbeam-ndr-vlan": "120",
                "sunbeam-ndr-address": "192.0.2.3/28",
            },
            "tag": 120,
            "vlan_mode": vlan_mode,
            "trunks": trunks,
        },
        {"type": "internal"},
    ]
    host.ovs.vsctl.return_value = "br-ex"

    if valid:
        attachments, _ = host.resolve([declaration])
        assert attachments[0].vlan == 120
    else:
        with pytest.raises(ValueError, match="Conflicting NDR peering interface"):
            host.resolve([declaration])


def test_reject_dedicated_vlan_on_provider_uplink(host):
    host.links["uplink122"]["link"] = "eno2"
    with pytest.raises(ValueError, match="must be outside the provider bridge"):
        host.resolve(
            [_instance("blue", "dedicated-uplink", "ipv6", interface="uplink122")]
        )


def test_address_readiness_waits_for_ipv6_dad(host):
    attachments, _ = host.resolve(
        [_instance("blue", "dedicated-uplink", "ipv6", interface="uplink122")]
    )
    entry = host.links["uplink122"]["addr_info"][0]
    entry["tentative"] = True
    assert host.ready(attachments) == set()
    entry.pop("tentative")
    assert host.ready(attachments) == {"blue"}


def test_protection_precedes_managed_port_creation(host, monkeypatch):
    attachments, _ = host.resolve(
        [
            _instance(
                "red",
                "provider-trunk",
                "ipv4",
                physnet="physnet1",
                vlan=120,
                address="192.0.2.3/28",
            )
        ]
    )
    timeline = Mock()
    monkeypatch.setattr(ndr_peering.subprocess, "run", timeline.nft)
    host.ovs.vsctl = timeline.ovs

    host.apply(attachments, rewrite_firewall=True)

    assert [event[0] for event in timeline.mock_calls] == ["nft", "ovs"]
    batch = timeline.nft.call_args.kwargs["input"]
    assert "ip daddr { 192.0.2.3 } counter drop" in batch
    assert timeline.ovs.call_args.args[:3] == (
        "add-port",
        "br-ex",
        attachments[0].interface,
    )
    assert "vlan_mode=access" in timeline.ovs.call_args.args


@pytest.mark.parametrize(
    "port_settings",
    [
        {"tag": 123, "vlan_mode": "access", "trunks": []},
        {"tag": 120, "vlan_mode": "native-tagged", "trunks": [121]},
    ],
)
def test_refuse_removing_owned_port_with_vlan_drift(host, port_settings):
    name = ndr_peering._interface_name("red")
    metadata = {
        "sunbeam-ndr-domain": "red",
        "sunbeam-ndr-bridge": "br-ex",
        "sunbeam-ndr-vlan": "120",
    }
    host.ovs.find.return_value = {
        "headings": ["name", "external_ids"],
        "data": [[name, ["map", list(metadata.items())]]],
    }
    host.ovs.list_table.side_effect = [
        {"external_ids": metadata, **port_settings},
        {"type": "internal"},
    ]
    host.ovs.vsctl.return_value = "br-ex"

    with pytest.raises(ValueError, match="Cannot safely remove"):
        host.apply([], rewrite_firewall=False)

    host.ovs.del_port.assert_not_called()


@pytest.mark.parametrize("include_ipv6", [False, True], ids=["single", "dual-stack"])
def test_firewall_protects_peering_addresses_and_blocks_linux_transit(include_ipv6):
    ipv4 = ndr_peering.Attachment("red", "peering4", ip_interface("192.0.2.3/28"))
    ipv6 = ndr_peering.Attachment("blue", "peering6", ip_interface("2001:db8::3/64"))

    attachments = [ipv4, ipv6] if include_ipv6 else [ipv4]
    batch = ndr_peering.NDRPeering.firewall_batch(attachments)

    ports = ", ".join(f'"{item.interface}"' for item in attachments)
    assert f"elements = {{ {ports} }}" in batch
    assert "ip daddr { 192.0.2.3 } counter drop" in batch
    assert ("ip6 daddr { 2001:db8::3 } counter drop" in batch) is include_ipv6
    forward = batch.split("chain forward {", 1)[1]
    assert "iifname @peering_ports counter drop" in forward
    assert "oifname @peering_ports counter drop" in forward


def test_empty_firewall_batch_only_removes_the_ndr_table():
    assert ndr_peering.NDRPeering.firewall_batch([]) == (
        "add table inet sunbeam_dynamic_routing\n"
        "delete table inet sunbeam_dynamic_routing\n"
    )
