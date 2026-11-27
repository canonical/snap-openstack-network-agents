#!/bin/bash
# Regenerate tools/openstack-network-agents.plugs.data from the 'plugs'
# section of the openstack-network-agents snap-declaration as published in
# the Snap Store. Requires snapd with store access and python3 with PyYAML.
set -euo pipefail

cd "$(dirname "$0")/.."

snap_name="openstack-network-agents"
out="tools/${snap_name}.plugs.data"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

snap known snap-declaration snap-name="${snap_name}" \
	| sed '/^$/Q' \
	| python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)["plugs"], indent=2))' \
	> "${tmp}"

mv "${tmp}" "${out}"