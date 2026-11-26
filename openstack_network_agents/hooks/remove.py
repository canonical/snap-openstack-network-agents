# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Clean up NDR host resources when the snap is removed."""

import logging
import subprocess

from snaphelpers import Snap

from openstack_network_agents.core.ndr_host import NDRHost
from openstack_network_agents.hooks.log import setup_logging

logger = logging.getLogger(__name__)


def hook(snap: Snap) -> None:
    """Clean up after snapd stops services and before it disconnects interfaces."""
    setup_logging(snap.paths.common / "hooks.log")
    try:
        NDRHost(snap).cleanup_after_stop()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        logger.warning("Could not clean up NDR host resources: %s", error)
