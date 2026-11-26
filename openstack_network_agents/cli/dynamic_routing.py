# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import subprocess
import time

import click
from snaphelpers import Snap

from openstack_network_agents.core.ndr_host import HostState, NDRHost, validate

logger = logging.getLogger(__name__)
_RECONCILE_ERRORS = (
    KeyError,
    TypeError,
    ValueError,
    RuntimeError,
    OSError,
    subprocess.SubprocessError,
)


@click.group()
def dynamic_routing() -> None:
    """Validate and reconcile local dynamic routing attachments."""


@dynamic_routing.command("validate")
@click.pass_obj
def validate_instances(snap: Snap) -> None:
    """Validate the JSON instance list on standard input."""
    try:
        instances = json.load(click.get_text_stream("stdin"))
        result = validate(snap, instances)
    except _RECONCILE_ERRORS as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(json.dumps(result, sort_keys=True))


@dynamic_routing.command("reconcile")
@click.pass_obj
def reconcile_instances(snap: Snap) -> None:
    """Activate placement once the planned interface addresses are ready."""
    host = NDRHost(snap)
    try:
        state = host.reconcile()
    except _RECONCILE_ERRORS as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(json.dumps({"ready": state.peerings_ready}))


@dynamic_routing.command("watch", hidden=True)
@click.pass_obj
def watch(snap: Snap) -> None:
    """Restore NDR host readiness independently of Pebble startup."""
    host = NDRHost(snap)
    state: HostState | None = None
    while True:
        try:
            current = host.reconcile(polling=True)
            if current != state:
                logger.info("NDR host entered state %s", current)
                state = current
        except _RECONCILE_ERRORS as exc:
            logger.warning("NDR host attachment not ready: %s", exc)
        time.sleep(5)
