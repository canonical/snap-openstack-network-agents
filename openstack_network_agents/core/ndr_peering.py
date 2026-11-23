# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import hashlib
import ipaddress
import json
import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from sunbeam_ndr_contract import (
    DedicatedUplink,
    Instance,
    ProviderTrunk,
    is_usable_peering_address,
)

from openstack_network_agents.core.bridge_datapath import OVSCli, OVSCommandError
from openstack_network_agents.core.templates import get_template

_OWNER = "sunbeam-ndr-domain"
_BRIDGE = "sunbeam-ndr-bridge"
_VLAN = "sunbeam-ndr-vlan"
_ADDRESS = "sunbeam-ndr-address"
_TABLE = "sunbeam_dynamic_routing"


def _tool(path: str) -> str:
    snap = os.environ.get("SNAP")
    return str(Path(snap) / "usr/sbin" / path) if snap else path


@dataclass(frozen=True)
class Attachment:
    domain: str
    interface: str
    address: ipaddress.IPv4Interface | ipaddress.IPv6Interface
    bridge: str | None = None
    vlan: int | None = None
    available: bool = True


def _interface_name(domain: str) -> str:
    return "ndr-" + hashlib.sha256(domain.encode()).hexdigest()[:11]


def _is_access_port(port: dict) -> bool:
    # With a tag set, OVS treats an unset VLAN mode as access.
    return port.get("vlan_mode") in ([], "access") and port.get("trunks") == []


def _links() -> dict[str, dict]:
    output = subprocess.check_output(
        [_tool("ip"), "-j", "-d", "address", "show"], timeout=15
    )
    return {link["ifname"]: link for link in json.loads(output)}


def _addresses(link: dict, family: int) -> list[tuple[dict, str]]:
    return [
        (entry, f"{entry['local']}/{entry['prefixlen']}")
        for entry in link.get("addr_info", [])
        if "local" in entry
        and entry.get("scope") == "global"
        and ipaddress.ip_address(entry["local"]).version == family
        and is_usable_peering_address(ipaddress.ip_address(entry["local"]))
    ]


class NDRPeering:
    """Resolve and maintain only the host resources dedicated to NDR."""

    def __init__(self, ovs: OVSCli) -> None:
        self.ovs = ovs
        self.links = _links()
        self.bridges = self.ovs.get_bridge_physnet_map()
        self.bridge_interfaces = {
            interface
            for bridge in self.bridges
            for interface in self.ovs.list_bridge_interfaces(bridge)
        } | self.bridges.keys()

    def _bridge(self, interface: str) -> str | None:
        try:
            return self.ovs.vsctl(
                "port-to-br", interface, skip_transaction=True
            ).strip()
        except OVSCommandError:
            return None

    def _port(self, interface: str) -> dict:
        return self.ovs.list_table(
            "Port", interface, ["external_ids", "tag", "vlan_mode", "trunks"]
        )

    def _check_managed_port(self, attachment: Attachment) -> None:
        interface = attachment.interface
        port = self._port(interface)
        if not port and interface not in self.links:
            return
        existing_type = self.ovs.list_table("Interface", interface, ["type"]).get(
            "type"
        )
        metadata = port.get("external_ids", {})
        if (
            metadata.get(_OWNER) != attachment.domain
            or metadata.get(_ADDRESS) != str(attachment.address)
            or metadata.get(_BRIDGE) != attachment.bridge
            or metadata.get(_VLAN) != str(attachment.vlan)
            or port.get("tag") != attachment.vlan
            or not _is_access_port(port)
            or existing_type != "internal"
            or self._bridge(interface) != attachment.bridge
        ):
            raise ValueError(
                f"Conflicting NDR peering interface {interface}. Drain it before replacing it."
            )

    def _provider(self, domain: str, trunk: ProviderTrunk) -> Attachment:
        bridges = [
            bridge for bridge, name in self.bridges.items() if name == trunk.physnet
        ]
        if len(bridges) != 1:
            raise ValueError(
                f"NDR physnet {trunk.physnet} must resolve to exactly one local bridge."
            )
        attachment = Attachment(
            domain, _interface_name(domain), trunk.address, bridges[0], trunk.vlan
        )
        self._check_managed_port(attachment)
        return attachment

    def _dedicated(
        self,
        domain: str,
        family: int,
        uplink: DedicatedUplink,
        allow_unavailable: bool,
    ) -> Attachment:
        interface = uplink.interface
        selected = uplink.address
        link = self.links.get(interface)
        if link is None:
            if allow_unavailable and selected is not None:
                return Attachment(
                    domain, interface, ipaddress.ip_interface(selected), available=False
                )
            raise ValueError(f"NDR dedicated interface {interface} does not exist.")
        kind = link.get("linkinfo", {}).get("info_kind")
        parent = link.get("link")
        if parent is None and "link_index" in link:
            parent = next(
                (
                    name
                    for name, item in self.links.items()
                    if item.get("ifindex") == link["link_index"]
                ),
                None,
            )
        if (
            interface in self.bridge_interfaces
            or link.get("master")
            or "LOOPBACK" in link.get("flags", [])
            or kind in {"bridge", "openvswitch"}
            or (kind == "vlan" and (not parent or parent in self.bridge_interfaces))
        ):
            raise ValueError(
                f"NDR dedicated interface {interface} must be outside the provider bridge."
            )
        candidates = [
            ipaddress.ip_interface(cidr)
            for entry, cidr in _addresses(link, family)
            if selected is None or entry["local"] == str(selected)
        ]
        if not candidates and allow_unavailable and selected is not None:
            return Attachment(
                domain, interface, ipaddress.ip_interface(selected), available=False
            )
        if len(candidates) != 1:
            raise ValueError(
                f"NDR dedicated interface {interface} needs one matching IPv{family} address."
            )
        return Attachment(domain, interface, candidates[0])

    def resolve(
        self, instances: Sequence[Instance], *, allow_unavailable: bool = False
    ) -> tuple[list[Attachment], list[dict[str, object]]]:
        """Validate placement against the local OVS and kernel state."""
        attachments = []
        normalized = []
        for item in instances:
            domain = item.agent.domain
            peering = item.peering
            if peering is None:
                raise ValueError(
                    f"NDR domain {domain} needs exactly one peering attachment."
                )
            declaration: dict[str, dict[str, object]]
            if isinstance(peering, ProviderTrunk):
                attachment = self._provider(domain, peering)
                declaration = {
                    "provider-trunk": {
                        "physnet": peering.physnet,
                        "vlan": peering.vlan,
                        "address": str(attachment.address),
                    }
                }
            else:
                attachment = self._dedicated(
                    domain, item.ip_version, peering, allow_unavailable
                )
                declaration = {
                    "dedicated-uplink": {
                        "interface": peering.interface,
                        "address": str(attachment.address.ip),
                    }
                }
            attachments.append(attachment)
            normalized.append({**item.declaration, "peering": declaration})
        self._check_uniqueness(attachments)
        return attachments, normalized

    def _check_uniqueness(self, attachments: list[Attachment]) -> None:
        if len({item.interface for item in attachments}) != len(attachments):
            raise ValueError(
                "An NDR peering interface must be exclusive to one domain."
            )
        if len({item.address.ip for item in attachments}) != len(attachments):
            raise ValueError("An NDR peering address must be exclusive to one domain.")
        provider = [item for item in attachments if item.bridge]
        if len({(item.bridge, item.vlan) for item in provider}) != len(provider):
            raise ValueError(
                "An NDR provider bridge and VLAN pair must be exclusive to one domain."
            )
        for item in attachments:
            if any(
                name != item.interface and address["local"] == str(item.address.ip)
                for name, link in self.links.items()
                for address, _ in _addresses(link, item.address.version)
            ):
                raise ValueError(
                    f"NDR peering address {item.address.ip} is in use on another interface."
                )

    def _owned_ports(self) -> dict[str, str]:
        rows = self.ovs.find("Port", f"external_ids:{_OWNER}!=[]")
        result = {}
        for row in rows["data"]:
            record = dict(zip(rows["headings"], row, strict=True))
            external_ids = record.get("external_ids", [])
            if len(external_ids) != 2 or external_ids[0] != "map":
                continue
            domain = dict(external_ids[1]).get(_OWNER)
            if domain and record["name"] == _interface_name(domain):
                result[record["name"]] = domain
        return result

    def managed_ports_match(self, attachments: list[Attachment]) -> bool:
        """Check desired and observed OVS port names independently of IP readiness."""
        return self._owned_ports().keys() == {
            item.interface for item in attachments if item.bridge
        }

    def _remove_ports(self, keep: set[str]) -> None:
        for interface, domain in self._owned_ports().items():
            if interface in keep:
                continue
            port = self._port(interface)
            interface_type = self.ovs.list_table("Interface", interface, ["type"]).get(
                "type"
            )
            bridge = self._bridge(interface)
            metadata = port.get("external_ids", {})
            if (
                not bridge
                or metadata.get(_OWNER) != domain
                or metadata.get(_BRIDGE) != bridge
                or metadata.get(_VLAN) != str(port.get("tag"))
                or type(port.get("tag")) is not int
                or not 1 <= port["tag"] <= 4094
                or not _is_access_port(port)
                or interface_type != "internal"
            ):
                raise ValueError(
                    f"Cannot safely remove NDR peering interface {interface}."
                )
            self.ovs.del_port(bridge, interface)

    def apply(self, attachments: list[Attachment], rewrite_firewall: bool) -> None:
        """Protect desired attachments and create owned ports after protection is up."""
        managed = [item for item in attachments if item.bridge]
        self._remove_ports({item.interface for item in managed})
        if rewrite_firewall:
            command = [_tool("nft"), "-f", "-"]
            subprocess.run(
                command,
                input=self.firewall_batch(attachments),
                text=True,
                check=True,
                timeout=15,
            )
        for item in managed:
            if item.bridge and not self._port(item.interface):
                self.ovs.vsctl(
                    "add-port",
                    item.bridge,
                    item.interface,
                    "--",
                    "set",
                    "Port",
                    item.interface,
                    f"tag={item.vlan}",
                    "vlan_mode=access",
                    f"external_ids:{_OWNER}={item.domain}",
                    f"external_ids:{_BRIDGE}={item.bridge}",
                    f"external_ids:{_VLAN}={item.vlan}",
                    f"external_ids:{_ADDRESS}={item.address}",
                    "--",
                    "set",
                    "Interface",
                    item.interface,
                    "type=internal",
                )

    @staticmethod
    def firewall_batch(attachments: list[Attachment]) -> str:
        """Render the complete desired firewall transaction."""
        return get_template("ndr-firewall.nft.j2").render(
            table=_TABLE,
            attachments=attachments,
            ipv4_addresses=[
                item.address.ip for item in attachments if item.address.version == 4
            ],
            ipv6_addresses=[
                item.address.ip for item in attachments if item.address.version == 6
            ],
        )

    @classmethod
    def check_firewall(cls, attachments: list[Attachment]) -> None:
        subprocess.run(
            [_tool("nft"), "--check", "-f", "-"],
            input=cls.firewall_batch(attachments),
            text=True,
            check=True,
            timeout=15,
        )

    @staticmethod
    def firewall_fingerprint() -> str | None:
        """Read the complete live ruleset without mutable packet counters."""
        result = subprocess.run(
            [_tool("nft"), "-s", "-n", "list", "table", "inet", _TABLE],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        return (
            hashlib.sha256(result.stdout).hexdigest()
            if result.returncode == 0
            else None
        )

    def ready(
        self, attachments: list[Attachment], verify_ports: bool = False
    ) -> set[str]:
        links = _links()
        ready = set()
        for attachment in attachments:
            if not attachment.available:
                continue
            if (
                verify_ports
                and attachment.bridge
                and not self._port(attachment.interface)
            ):
                continue
            link = links.get(attachment.interface, {})
            if "UP" not in link.get("flags", []):
                continue
            for entry, cidr in _addresses(link, attachment.address.version):
                flags = set(entry.get("flags", []))
                invalid = {"tentative", "dadfailed"}
                if (
                    ipaddress.ip_interface(cidr) == attachment.address
                    and not flags.intersection(invalid)
                    and not any(entry.get(flag) for flag in invalid)
                ):
                    ready.add(attachment.domain)
        return ready
