# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import click
from snaphelpers import Snap

from openstack_network_agents.cli.log import setup_root_logging
from openstack_network_agents.cli.nics import list_nics
from openstack_network_agents.cli.setup_bridge import setup_bridge
from openstack_network_agents.cli.show_bridge_setup import show_bridge_setup

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


@click.group("init", context_settings=CONTEXT_SETTINGS)
@click.option("-v", "--verbose", is_flag=True, help="Increase output verbosity")
def cli(verbose: bool):
    """Set of utilities for managing the agents."""


def main():
    """Register commands and run the CLI."""
    snap = Snap()
    setup_root_logging()
    cli.add_command(setup_bridge)
    cli.add_command(show_bridge_setup)
    cli.add_command(list_nics)

    cli(obj=snap)


if __name__ == "__main__":
    main()
