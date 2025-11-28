# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import glob
import logging
import pathlib
from typing import Iterable

import pydantic
from pyroute2.ndb.objects.interface import Interface

logger = logging.getLogger(__name__)


class InterfaceOutput(pydantic.BaseModel):
    """Output schema for an interface."""

    name: str = pydantic.Field(description="Main name of the interface", default="")
    configured: bool = pydantic.Field(
        description="Whether the interface has an IP address configured",
        default=False,
    )
    up: bool = pydantic.Field(description="Whether the interface is up", default=False)
    connected: bool = pydantic.Field(
        description="Whether the interface is connected", default=False
    )


class NicList(pydantic.RootModel[list[InterfaceOutput]]):
    """Root schema for a list of interfaces."""


def to_output_schema(nics: list[Interface]) -> NicList:  # noqa: C901
    """Convert the interfaces to the output schema."""
    nics_ = []

    for nic in nics:
        ifname = nic["ifname"]

        out = InterfaceOutput(
            name=ifname,
            configured=is_interface_configured(nic),
            up=is_nic_up(nic),
            connected=is_nic_connected(nic),
        )

        nics_.append(out)

    return NicList(nics_)


def get_interfaces(ndb) -> list[Interface]:
    """Get all interfaces from the system."""
    interfaces = []
    iface_view = ndb.interfaces
    for key in iface_view.keys():
        try:
            interfaces.append(iface_view[key])
        except KeyError:
            # Happens when interfaces are deleted while we are iterating.
            logger.debug("Interface %s not found in the NDB view", key)
    return interfaces


def load_virtual_interfaces() -> list[str]:
    """Load virtual interfaces from the system."""
    virtual_nic_dir = "/sys/devices/virtual/net/*"
    return [pathlib.Path(p).name for p in glob.iglob(virtual_nic_dir)]


def is_link_local(address: str) -> bool:
    """Check if address is link local."""
    return address.startswith("fe80")


def is_interface_configured(nic: Interface) -> bool:
    """Check if interface has an IP address configured."""
    ipaddr = nic.ipaddr
    if ipaddr is None:
        return False
    for record in ipaddr.summary():
        if (ip := record["address"]) and not is_link_local(ip):
            logger.debug("Interface %r has IP address %r", nic["ifname"], ip)
            return True
    return False


def is_nic_connected(interface: Interface) -> bool:
    """Check if nic is physically connected."""
    return interface["operstate"].lower() == "up"


def is_nic_up(interface: Interface) -> bool:
    """Check if nic is up."""
    return interface["state"].lower() == "up"


def filter_candidate_nics(nics: Iterable[Interface]) -> list[str]:
    """Return a list of candidate nics.

    Candidate nics are:
      - not part of a bond
      - not a virtual nic except for bond and vlan
      - not configured (unless include_configured is True)
    """
    configured_nics = []
    virtual_nics = load_virtual_interfaces()
    for nic in nics:
        ifname = nic["ifname"]
        logger.debug("Checking interface %r", ifname)

        if nic["slave_kind"] == "bond":
            logger.debug("Ignoring interface %r, it is part of a bond", ifname)
            continue

        if ifname in virtual_nics:
            kind = nic["kind"]
            if kind in ("bond", "vlan"):
                logger.debug("Interface %r is a %s", ifname, kind)
            else:
                logger.debug(
                    "Ignoring interface %r, it is a virtual interface, kind: %s",
                    ifname,
                    kind,
                )
                continue

        is_configured = is_interface_configured(nic)
        logger.debug("Interface %r is configured: %r", ifname, is_configured)
        logger.debug("Adding interface %r as a candidate", ifname)
        configured_nics.append(ifname)

    return configured_nics
