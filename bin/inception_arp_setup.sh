#!/bin/bash

# This script is for configuring Open vSwitch to intercept all ARP
# requests through it, while all other traffic remains unaffected.

CONTROLLER_IP=10.2.184.75
BRIDGE_NAME=obr1
APR_PRIORITY=20
NORMAL_PRIORITY=10

# Connect the OVS to the controller
sudo ovs-vsctl set-controller $BRIDGE_NAME tcp:$CONTROLLER_IP:6633

# Configure the controller to be out of band.  With controller "in
# band", Open vSwitch sets up special "hidden" flows to make sure that
# traffic can make it back and forth between OVS and the controller.
# These hidden flows are removed when controller is set "out of band"
sudo ovs-vsctl set controller $BRIDGE_NAME connection-mode=out-of-band

# Set fail-mode to secure so that when the connection to the
# controller is lost, OVS will not perform normal (traditional) L2/L3
# functionality
sudo ovs-vsctl set bridge $BRIDGE_NAME fail-mode=secure

# Flush all existing flows
sudo ovs-ofctl del-flows $BRIDGE_NAME

# Flow 1 intercepts all ARP requests
sudo ovs-ofctl add-flow $BRIDGE_NAME "table=0, dl_type=0x0806, \
  priority=$APR_PRIORITY, actions=controller"

# Flow 2 orders all other traffic to go as usual
sudo ovs-ofctl add-flow $BRIDGE_NAME "table=0, \
  priority=$NORMAL_PRIORITY, actions=NORMAL"
