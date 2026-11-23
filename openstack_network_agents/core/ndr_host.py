# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import fcntl
import hashlib
import json
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum

from snaphelpers import Snap
from sunbeam_ndr_contract import CONTRACT_VERSION, ValidationResult, parse_instances

from openstack_network_agents.core.bridge_datapath import OVSCli
from openstack_network_agents.core.common import ovs_switch_socket
from openstack_network_agents.core.constants import OVS_CLI_DEFAULT_TIMEOUT
from openstack_network_agents.core.dynamic_routing import (
    DynamicRouting,
    NDRConfig,
    _read,
    _write_private,
    parse_config,
)
from openstack_network_agents.core.ndr_peering import NDRPeering

_WATCH_APP = "openstack-network-agents.ndr-host"


class HostState(StrEnum):
    """Outcome of a host reconciliation, derived from config and live state."""

    DISABLED = "disabled"
    WAITING_FOR_PLACEMENT = "waiting for a peering plan"
    WAITING_FOR_PEERINGS = "waiting for protected peering addresses"
    PAUSED = "peerings ready, waiting for AMQP credentials"
    READY = "peerings ready"

    @property
    def peerings_ready(self) -> bool:
        """Report whether the placement needs further peering address setup."""
        return self in (HostState.DISABLED, HostState.PAUSED, HostState.READY)


def _host(snap: Snap) -> NDRPeering:
    return NDRPeering(OVSCli(ovs_switch_socket(snap), timeout=OVS_CLI_DEFAULT_TIMEOUT))


def validate(snap: Snap, instances: object) -> ValidationResult:
    """Check the complete per-unit contract before applying any resources."""
    placement = parse_instances(instances)
    if not placement:
        return {
            "contract-version": CONTRACT_VERSION,
            "instances": [],
            "managed-addresses": {},
        }
    peering = _host(snap)
    attachments, normalized = peering.resolve(placement)
    peering.check_firewall(attachments)
    return {
        "contract-version": CONTRACT_VERSION,
        "instances": normalized,
        "managed-addresses": {
            item.interface: str(item.address) for item in attachments if item.bridge
        },
    }


class NDRHost:
    """Reconcile host resources and runnable services from the same snap config."""

    def __init__(self, snap: Snap) -> None:
        self.snap = snap
        self.directory = snap.paths.common / "ndr"
        self.firewall_state = self.directory / "host-protection"
        self.routing = DynamicRouting(snap.paths.common, snap.paths.snap)
        self.last_applied: str | None = None

    def validate_pending_config(self, raw: object) -> NDRConfig:
        """Validate pending settings before the configure hook changes the host."""
        config = parse_config(raw)
        if config.ca_cert:
            self.routing.verify_tls_support()
        return config

    def schedule_reconcile(self, config: NDRConfig) -> None:
        """Enable the watcher to apply the configuration after snapd commits it."""
        if (
            any(item.peering is not None for item in config.placement)
            or self.firewall_state.exists()
            or self.routing.has_state()
        ):
            subprocess.run(
                ["snapctl", "start", "--enable", _WATCH_APP], check=True, timeout=35
            )

    def reconcile(self, *, polling: bool = False) -> HostState:
        """Reconcile committed configuration and derive the resulting host state.

        The configure hook does not modify host resources. Both the charm and
        the watcher use this locked path after snapd commits the configuration.
        """
        with self._reconcile_lock():
            options = self.snap.config.get_options("ndr")
            raw = options.get("ndr.config")
            return self._reconcile(parse_config(raw), _digest(raw), polling)

    def cleanup_after_stop(self) -> None:
        """Retire owned host resources after snapd has stopped the services."""
        if not self.firewall_state.exists():
            return
        with self._reconcile_lock():
            if self.firewall_state.exists():
                # Keep the firewall if we cannot safely remove the owned OVS ports.
                _host(self.snap).apply([], rewrite_firewall=True)
                self.firewall_state.unlink()

    @contextmanager
    def _reconcile_lock(self) -> Iterator[None]:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.directory / "host-reconcile.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _reconcile(
        self,
        config: NDRConfig,
        generation: str,
        polling: bool,
    ) -> HostState:
        peered = [item for item in config.placement if item.peering is not None]
        manage_agents = bool(peered and config.transport)
        if not manage_agents:
            # Disablement and AMQP loss stop the old agents before any host changes.
            if not config.placement:
                self.routing.apply([], disable_supervisor=True)
            else:
                self.routing.apply([])
            if not peered and not self.firewall_state.exists():
                return self._peerings_state(config, set())
        host = _host(self.snap)
        try:
            # The watcher can retain protection for a known dedicated address
            # while its interface or address is temporarily unavailable.
            attachments, _ = host.resolve(peered, allow_unavailable=True)
        except KeyError, TypeError, ValueError:
            if manage_agents:
                self.routing.apply([])
            self.last_applied = None
            raise
        intended = _digest(host.firewall_batch(attachments))
        observed = host.firewall_fingerprint()
        previous_intent, _, previous_firewall = _read(self.firewall_state).partition(
            "\n"
        )
        protected = bool(observed) and observed == previous_firewall
        ready = host.ready(attachments, verify_ports=True) if protected else set()
        active = {agent.service for agent in config.agents_for(ready)}
        rewrite = not protected or intended != previous_intent
        request = _digest([generation, sorted(active)])
        if (
            polling
            and not rewrite
            and self.last_applied == request
            and self.routing.services_started(active)
            and host.managed_ports_match(attachments)
        ):
            return self._peerings_state(config, ready)
        if manage_agents:
            self.routing.stop_unwanted(active)
            if config.ca_cert:
                self.routing.verify_tls_support()
        if peered and not self.firewall_state.exists():
            # Record ownership immediately before the first host mutation.
            _write_private(self.firewall_state, "")
        host.apply(attachments, rewrite_firewall=rewrite)
        if rewrite and attachments:
            observed = host.firewall_fingerprint()
            if observed is None:
                raise RuntimeError("NDR firewall rules did not become visible.")
            _write_private(self.firewall_state, f"{intended}\n{observed}")
        ready = host.ready(attachments)
        runnable = config.agents_for(ready)
        if manage_agents:
            self.routing.apply(
                runnable,
                transport=config.transport,
                ca_cert=config.ca_cert,
            )
        if not attachments:
            self.firewall_state.unlink(missing_ok=True)
        self.last_applied = _digest(
            [generation, sorted(agent.service for agent in runnable)]
        )
        return self._peerings_state(config, ready)

    @staticmethod
    def _peerings_state(config: NDRConfig, ready: set[str]) -> HostState:
        if not config.placement:
            return HostState.DISABLED
        if not any(item.peering is not None for item in config.placement):
            return HostState.WAITING_FOR_PLACEMENT
        if any(
            item.peering is None or item.agent.domain not in ready
            for item in config.placement
        ):
            return HostState.WAITING_FOR_PEERINGS
        if not config.transport:
            return HostState.PAUSED
        return HostState.READY


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
