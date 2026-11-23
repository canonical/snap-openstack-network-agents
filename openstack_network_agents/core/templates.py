# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Render configuration from templates shipped with the Python package."""

from jinja2 import Environment, PackageLoader, StrictUndefined, Template

_environment = Environment(
    loader=PackageLoader("openstack_network_agents"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
)


def get_template(name: str) -> Template:
    """Load a configuration template by name."""
    return _environment.get_template(name)
