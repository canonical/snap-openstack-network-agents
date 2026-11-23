# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from importlib.metadata import entry_points
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openstack_network_agents.hooks import remove


def test_remove_hook_logs_cleanup_failure_and_allows_uninstall(tmp_path, caplog):
    snap = Mock(paths=SimpleNamespace(common=tmp_path))
    hook = next(iter(entry_points(group="snaphelpers.hooks", name="remove"))).load()
    with (
        patch.object(remove, "setup_logging"),
        patch.object(remove, "NDRHost") as host,
    ):
        host.return_value.cleanup_after_stop.side_effect = RuntimeError("OVSDB offline")
        hook(snap)

    host.assert_called_once_with(snap)
    host.return_value.cleanup_after_stop.assert_called_once_with()
    assert "Could not clean up NDR host resources: OVSDB offline" in caplog.text
