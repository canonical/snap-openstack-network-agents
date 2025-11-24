# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging

import click
import prettytable
import pyroute2
from snaphelpers import Snap

from openstack_network_agents.cli.common import (
    JSON_FORMAT,
    JSON_INDENT_FORMAT,
    TABLE_FORMAT,
    VALUE_FORMAT,
)
from openstack_network_agents.core.nics import (
    NicList,
    filter_candidate_nics,
    get_interfaces,
    to_output_schema,
)

logger = logging.getLogger(__name__)


def display_nics(nics: NicList, candidate_nics: list[str], format: str):
    """Display the result depending on the format."""
    if format in (VALUE_FORMAT, TABLE_FORMAT):
        table = prettytable.PrettyTable()
        table.title = "All NICs"
        table.field_names = [
            "Name",
            "Configured",
            "Up",
            "Connected",
        ]
        for nic in nics.root:
            table.add_row(
                [
                    nic.name,
                    nic.configured,
                    nic.up,
                    nic.connected,
                ]
            )
        print(table)

        if candidate_nics:
            table = prettytable.PrettyTable()
            table.title = "Candidate NICs"
            table.field_names = ["Name"]
            for candidate in candidate_nics:
                table.add_row([candidate])
            print(table)
    elif format in (JSON_FORMAT, JSON_INDENT_FORMAT):
        indent = 2 if format == JSON_INDENT_FORMAT else None
        print(
            json.dumps(
                {"nics": nics.model_dump(), "candidates": candidate_nics}, indent=indent
            )
        )


@click.command("list-nics")
@click.option(
    "-f",
    "--format",
    default=JSON_FORMAT,
    type=click.Choice([VALUE_FORMAT, TABLE_FORMAT, JSON_FORMAT, JSON_INDENT_FORMAT]),
    help="Output format",
)
@click.pass_obj
def list_nics(snap: Snap, format: str):
    """List nics that are candidates for use by OVN/OVS subsystem.

    This nic will be used by OVS to provide external connectivity to the VMs.
    """
    with pyroute2.NDB() as ndb:
        nics = get_interfaces(ndb)
        candidate_nics = filter_candidate_nics(nics)
        nics_ = to_output_schema(nics)
    display_nics(nics_, candidate_nics, format)
