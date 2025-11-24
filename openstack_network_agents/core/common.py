# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import typing

from snaphelpers import Snap, UnknownConfigKey

from openstack_network_agents.core.constants import OVN_CHASSIS_PLUG
from openstack_network_agents.hooks.common import is_connected, logger


def config_get(
    snap: Snap,
) -> typing.Callable[typing.Concatenate[str, ...], typing.Any]:
    """Get a config value with a default fallback.

    :param snap: the snap reference
    :type snap: Snap
    :return: a function that retrieves config values with a default
    :rtype: Callable[[str, Any], Any]
    """

    def _getter(key: str, default: typing.Any = None) -> typing.Any:
        try:
            return snap.config.get(key)
        except UnknownConfigKey:
            return default

    return _getter


def ovs_switch_socket(snap: Snap) -> str:
    """Get the OVSDB socket path.

    :param snap: the snap reference
    :type snap: Snap
    :return: the OVSDB socket path
    :rtype: Path
    """
    if not is_connected(OVN_CHASSIS_PLUG):
        logger.warning(f"{OVN_CHASSIS_PLUG} not connected; skipping configure.")
        raise RuntimeError(f"{OVN_CHASSIS_PLUG} not connected")
    return "unix:" + str(snap.paths.data / "microovn/chassis/switch/db.sock")
