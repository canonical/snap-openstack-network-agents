# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import logging

from snaphelpers import Snap

from openstack_network_agents.core.bridge_datapath import OVSCli
from openstack_network_agents.core.common import config_get, ovs_switch_socket
from openstack_network_agents.core.constants import (
    OVN_CHASSIS_PLUG,
    OVS_CLI_DEFAULT_TIMEOUT,
)
from openstack_network_agents.core.dynamic_routing import _write_private
from openstack_network_agents.core.external_networking import (
    configure_ovn_encap_ip,
    configure_ovn_external_networking,
)
from openstack_network_agents.core.ndr_host import NDRHost
from openstack_network_agents.hooks.common import (
    is_connected,
    update_default_config,
)
from openstack_network_agents.hooks.log import setup_logging

logger = logging.getLogger(__name__)


def _fingerprint(value: object) -> str:
    """Compare configuration without storing AMQP credentials."""
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _configure_ovn_external_networking(snap: Snap) -> None:
    """Configure OVN external networking.

    :param snap: the snap reference
    :type snap: Snap
    :return: None
    """
    logger.info("Configuring OVN external networking.")
    config = config_get(snap)
    socket_path = ovs_switch_socket(snap)
    ovs_cli = OVSCli(socket_path, timeout=OVS_CLI_DEFAULT_TIMEOUT)
    configure_ovn_encap_ip(
        config("network.ip-address"),
        ovs_cli,
    )
    configure_ovn_external_networking(
        config("network.bridge"),
        config("network.physnet"),
        config("network.interface"),
        config("network.bridge-mapping"),
        config("network.enable-chassis-as-gw") in ("true", True),
        config("network.external-bridge-address"),
        ovs_cli,
    )


def hook(snap: Snap) -> None:
    """Configure hook for the OpenStack Network Agents snap."""
    setup_logging(snap.paths.common / "hooks.log")
    logger.info("Running configure hook for OpenStack Network Agents snap.")
    update_default_config(snap)

    options = snap.config.get_options("network", "logging", "ndr")
    other_config = options.as_dict()
    ndr_settings = other_config.pop("ndr", None)
    ndr_host = NDRHost(snap)
    ndr_config = ndr_host.validate_pending_config(options.get("ndr.config"))
    ndr_host.routing.logs.mkdir(mode=0o755, parents=True, exist_ok=True)
    connected = is_connected(OVN_CHASSIS_PLUG)
    # snapd can copy SNAP_DATA across revisions. Reconcile OVN on refresh and
    # after the chassis plug becomes available, even if the settings match.
    other_digest = _fingerprint([snap.paths.snap.name, connected, other_config])
    ndr_digest = _fingerprint(ndr_settings)
    state_file = snap.paths.data / "configure-state"
    try:
        previous = state_file.read_text(encoding="ascii")
    except FileNotFoundError, UnicodeDecodeError:
        previous = ""
    previous_other, _, previous_ndr = previous.partition("\n")
    ndr_only = (
        previous_other == other_digest
        and len(previous_ndr) == len(ndr_digest)
        and previous_ndr != ndr_digest
    )

    if not connected:
        logger.warning(f"{OVN_CHASSIS_PLUG} not connected; skipping OVN configure.")
    elif not ndr_only:
        _configure_ovn_external_networking(snap)

    ndr_host.schedule_reconcile(ndr_config)
    state = f"{other_digest}\n{ndr_digest}"
    if state != previous:
        _write_private(state_file, state)
