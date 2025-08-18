# OpenStack Network Agents (snap)

This snap provides the `neutron-ovn-metadata-agent` and helpers for Sunbeam
**network-role** nodes. It is designed to be co-located with `microovn`.

## Install

```bash
sudo snap install openstack-network-agents --classic
```

**NOTE:** Classic confinement is required to access `/var/run/openvswitch/db.sock`.

## Configure

The snap can configure the provider bridge and physnet mapping:

```bash
sudo snap set openstack-network-agents \
  external-interface=enp6s0 \
  bridge-name=br-ex \
  physnet-name=physnet1
```

Then (re)start the agent:

```bash
sudo snap start openstack-network-agents.metadata-agent
```

## Service

```bash
sudo snap services openstack-network-agents
```
