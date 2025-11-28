# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging

from snaphelpers import Snap

from openstack_network_agents.hooks.common import update_default_config
from openstack_network_agents.hooks.log import setup_logging

logger = logging.getLogger(__name__)


def hook(snap: Snap) -> None:
    """Install hook for the OpenStack Network Agents snap."""
    setup_logging(snap.paths.common / "hooks.log")
    logger.info("Running install hook for OpenStack Network Agents snap.")
    update_default_config(snap)
