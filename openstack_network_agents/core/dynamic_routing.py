# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Reconcile local Neutron Dynamic Routing agents under Pebble."""

import ast
import json
import os
import shlex
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import NotRequired, TypedDict, cast

from sunbeam_ndr_contract import Agent, Instance, parse_instances

from openstack_network_agents.core.templates import get_template

_PEBBLE_APP = "openstack-network-agents.pebble"

Service = TypedDict(
    "Service",
    {
        "command": str,
        "override": str,
        "startup": str,
        "on-failure": str,
        "on-success": NotRequired[str],
    },
)


class PebbleLayer(TypedDict, total=False):
    services: dict[str, Service]


class ServiceStatus(TypedDict):
    current: str


@dataclass(frozen=True)
class NDRConfig:
    """Desired placement and optional broker credentials."""

    placement: tuple[Instance, ...] = ()
    transport: str = ""
    ca_cert: str = ""

    def agents_for(self, domains: set[str]) -> list[Agent]:
        """Select agents whose domains are ready and have broker credentials."""
        if not self.transport:
            return []
        return [
            item.agent
            for item in self.placement
            if item.peering is not None and item.agent.domain in domains
        ]


def parse_config(raw: object) -> NDRConfig:
    """Parse desired snap config, including paused placement from older charms."""
    if raw is None or raw == "":
        return NDRConfig()
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ValueError("NDR configuration must be a JSON object.") from None
    if not isinstance(raw, dict) or not isinstance(raw.get("instances"), list):
        raise TypeError("NDR configuration must contain an instances list.")

    instances = raw["instances"]
    if "paused-instances" in raw:
        if instances:
            raise ValueError("NDR placement cannot be both active and paused.")
        return NDRConfig(parse_instances(raw["paused-instances"], allow_legacy=True))
    placement = parse_instances(instances, allow_legacy=True)
    if not placement:
        return NDRConfig()

    transport = raw.get("transport-url")
    if transport is not None and (
        not isinstance(transport, str)
        or not transport.startswith("rabbit://")
        or any(ord(character) < 32 for character in transport)
    ):
        raise ValueError("NDR requires a valid RabbitMQ transport URL.")
    ca_cert = raw.get("ca-cert", "")
    if not isinstance(ca_cert, str):
        raise TypeError("NDR CA certificate must be a PEM string.")
    if ca_cert:
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(
                cadata=ca_cert
            )
        except ValueError, ssl.SSLError:
            raise ValueError("NDR CA certificate is not valid PEM.") from None
    return NDRConfig(placement, transport or "", ca_cert)


def _write_private(path: Path, contents: str) -> None:
    """Replace a configuration file without exposing partially written data."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, mode="w", encoding="utf-8", delete=False
    ) as temp:
        temp_path = Path(temp.name)
        try:
            temp.write(contents)
            temp.flush()
            temp_path.replace(path)
        finally:
            temp_path.unlink(missing_ok=True)


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


@dataclass(frozen=True)
class _PebbleInventory:
    layer: PebbleLayer
    legacy_services: set[str]
    configs: set[str]
    shared: bool

    @property
    def configured(self) -> set[str]:
        return self.layer.get("services", {}).keys() | self.legacy_services


class DynamicRouting:
    """Manage the NDR layer and agent configuration under shared Pebble."""

    def __init__(self, common: Path, snap_path: Path) -> None:
        self.directory = common / "ndr"
        self.logs = common / "ndr-logs"
        self.pebble_dir = common / "pebble"
        self.socket = self.pebble_dir / ".pebble.socket"
        self.layer = self.pebble_dir / "layers" / "001-ndr.yaml"
        self.legacy_layer = self.directory / "pebble" / "layers" / self.layer.name
        self.ca_file = self.directory / "rabbitmq-ca.pem"
        self.env = {**os.environ, "PEBBLE": str(self.pebble_dir)}
        self.pebble = snap_path / "bin" / "pebble"

    def _run_pebble(self, *args: str) -> None:
        result = subprocess.run(
            [str(self.pebble), *args],
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=35,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(f"NDR Pebble {args[0]} failed.")

    def guard_supervisor_start(self) -> None:
        """Pause legacy NDR services until host readiness has been checked."""
        if not (previous := _read(self.layer)):
            return
        plan = json.loads(previous)
        services = plan.get("services", {})
        if "log-targets" in plan or any(
            service.get("startup") != "disabled" for service in services.values()
        ):
            for service in services.values():
                service["startup"] = "disabled"
            _write_private(
                self.layer, json.dumps({"services": services}, sort_keys=True)
            )

    def _service_path(self, service: str) -> Path:
        return self.directory / "agents" / service

    def _render_agent(self, agent: Agent, transport: str, tls: bool) -> str:
        return get_template("ndr-agent.conf.j2").render(
            host=agent.host,
            state_path=self._service_path(agent.service) / "state",
            log_file=self.logs / f"{agent.service}.log",
            transport_url=transport,
            router_id=agent.router_id,
            tls=tls,
            ca_file=self.ca_file,
        )

    def verify_tls_support(self) -> None:
        """Reject a bundle that cannot enforce RabbitMQ peer identity."""
        driver = (
            self.pebble.parent.parent
            / "usr/lib/python3/dist-packages/oslo_messaging/_drivers/impl_rabbit.py"
        )
        tree = ast.parse(_read(driver))
        option = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "BoolOpt"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "ssl_enforce_hostname_verification"
            for node in ast.walk(tree)
        )
        forwards_hostname = any(
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "server_hostname"
            for method in ast.walk(tree)
            if isinstance(method, ast.FunctionDef)
            and method.name == "_fetch_ssl_params"
            for node in ast.walk(method)
        )
        if not (option and forwards_hostname):
            raise RuntimeError(
                "The bundled RabbitMQ client cannot verify the broker hostname."
            )

    def _render_service(self, service: str) -> Service:
        command = shlex.join(
            [
                "/bin/sh",
                "-c",
                (
                    'export PYTHONPATH="$SNAP/usr/lib/python3/dist-packages"; '
                    'exec "$SNAP/usr/bin/python3.14" "$SNAP/usr/bin/neutron-bgp-dragent" "$@"'
                ),
                "neutron-bgp-dragent",
                "--config-file",
                str(self._service_path(service) / "agent.conf"),
            ]
        )
        # Only the host reconciler may start a service after checking protection.
        return {
            "command": command,
            "override": "replace",
            "startup": "disabled",
            "on-failure": "ignore",
            "on-success": "ignore",
        }

    def _update_layer(self, services: dict[str, Service]) -> None:
        """Merge only the NDR layer into the running supervisor."""
        update = self.directory / "update.yaml"
        _write_private(update, json.dumps({"services": services}, sort_keys=True))
        try:
            self._run_pebble("add", "--combine", "ndr", str(update))
        finally:
            update.unlink(missing_ok=True)

    def has_state(self) -> bool:
        """Return whether there might be a saved NDR plan or interrupted update."""
        return (
            self.layer.exists()
            or self.legacy_layer.exists()
            or any(self.directory.glob("agents/*/agent.conf"))
        )

    def _inventory(self) -> _PebbleInventory:
        saved = _read(self.layer)
        legacy = _read(self.legacy_layer)
        return _PebbleInventory(
            layer=cast(PebbleLayer, json.loads(saved)) if saved else PebbleLayer(),
            legacy_services=set(json.loads(legacy)["services"]) if legacy else set(),
            configs={
                path.parent.name for path in self.directory.glob("agents/*/agent.conf")
            },
            shared=any(path != self.layer for path in self.layer.parent.glob("*.yaml")),
        )

    def _live_services(self) -> dict[str, ServiceStatus] | None:
        if not self.socket.exists():
            return None
        try:
            return self._list_services()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("The NDR Pebble supervisor is unreachable.") from error

    def _stop_supervisor(self) -> None:
        subprocess.run(
            ["snapctl", "stop", "--disable", _PEBBLE_APP], check=True, timeout=35
        )
        # A killed supervisor can leave its socket on disk.
        if self.socket.is_socket():
            self.socket.unlink(missing_ok=True)

    def stop_unwanted(self, keep: set[str]) -> None:
        """Stop removed NDR agents before retiring any host resources."""
        inventory = self._inventory()
        if not (unwanted := (inventory.configured | inventory.configs) - keep):
            return
        services = self._live_services() or {}
        if retired := {
            name
            for name in unwanted & services.keys()
            if services[name]["current"] != "inactive"
        }:
            self._run_pebble("stop", *sorted(retired))

    def services_started(self, names: set[str]) -> bool:
        """Check whether all NDR services cleared for startup are active."""
        if not names:
            return True
        services = self._live_services() or {}
        return all(
            name in services and services[name]["current"] == "active" for name in names
        )

    def _list_services(self) -> dict[str, ServiceStatus]:
        result = subprocess.run(
            [str(self.pebble), "services", "--format=json"],
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
            timeout=35,
        )
        return json.loads(result.stdout)["services"]

    def apply(
        self,
        agents: list[Agent],
        *,
        transport: str = "",
        ca_cert: str = "",
    ) -> None:
        """Reconcile instances while keeping unaffected BGP sessions running."""
        if not agents:
            ca_cert = ""
        inventory = self._inventory()
        configured = inventory.configured
        if not (agents or inventory.layer or configured or inventory.configs):
            return
        try:
            live = self._live_services()
        except RuntimeError:
            if agents or inventory.shared:
                raise
            live = None
        if live is None and not (agents or inventory.shared):
            # Stop the daemon through snapd before discarding its private files.
            self._stop_supervisor()

        previous_plan = inventory.layer
        current = previous_plan.get("services", {}).copy()
        if live is not None:
            # An interrupted reconcile may have started an agent before saving the layer.
            pending = inventory.configs - configured
            current.update(
                {name: self._render_service(name) for name in pending & live.keys()}
            )
        configured |= inventory.configs
        desired = {
            agent.service: self._render_service(agent.service) for agent in agents
        }
        agent_configs = {
            agent.service: self._render_agent(agent, transport, bool(ca_cert))
            for agent in agents
        }
        ca_changed = _read(self.ca_file) != ca_cert
        changed_configs = {
            name
            for name, config in agent_configs.items()
            if _read(self._service_path(name) / "agent.conf") != config
        }
        affected = [
            name
            for name in current
            if name not in desired
            or current[name] != desired[name]
            or ca_changed
            or name in changed_configs
        ]
        if live is not None and affected:
            self._run_pebble("stop", *affected)

        if ca_cert and ca_changed:
            _write_private(self.ca_file, ca_cert)
        if desired:
            self.logs.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name, config in agent_configs.items():
            service_path = self._service_path(name)
            (service_path / "state").mkdir(mode=0o700, parents=True, exist_ok=True)
            if name in changed_configs:
                _write_private(service_path / "agent.conf", config)

        plan: PebbleLayer = {"services": desired}
        removed = configured - desired.keys()
        if live is not None and (desired or current):
            # Pebble merges layers in memory. Disable removed entries there and
            # omit them from the on-disk layer for the next supervisor start.
            additions = dict(desired)
            for name in current.keys() - desired.keys():
                additions[name] = {**current[name], "startup": "disabled"}
            self._update_layer(additions)
            if desired:
                self._run_pebble("start", *desired)
        for name in removed:
            (self._service_path(name) / "agent.conf").unlink(missing_ok=True)
        if not ca_cert:
            self.ca_file.unlink(missing_ok=True)
        if desired:
            _write_private(self.layer, json.dumps(plan, sort_keys=True))
            if live is None:
                subprocess.run(
                    ["snapctl", "start", "--enable", _PEBBLE_APP],
                    check=True,
                    timeout=35,
                )
        else:
            # Retain the cleanup index until the services and files are retired.
            self.layer.unlink(missing_ok=True)
        self.legacy_layer.unlink(missing_ok=True)
