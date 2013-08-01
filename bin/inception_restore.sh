#!/bin/bash

# This script is to return all configurations of a switch
# into traditional ones

BRIDGE_NAME=obr1

# Deconnect from the controller
sudo ovs-vsctl del-controller $BRIDGE_NAME

# Set connection in-band. OVS will not install hidden flows
# to ensure traditional functionality when the controller is down
sudo ovs-vsctl set controller $BRIDGE_NAME connection-mode=in-band

# Delete fail-mode. When connection to the controller is lost,
# The virtual switch will act like a traditional switch
sudo ovs-vsctl del-fail-mode $BRIDGE_NAME

# Delete all Openflow flows
sudo ovs-ofctl del-flows $BRIDGE_NAME

# Add a flow for normal operation
sudo ovs-ofctl add-flow $BRIDGE_NAME "table=0, actions=NORMAL"