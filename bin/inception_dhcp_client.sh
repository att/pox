#!/bin/bash

BRIDGE_NAME=obr1
DHCP_PRIORITY=20

# Intercepts DHCP packets and send them to the controller
sudo ovs-ofctl add-flow $BRIDGE_NAME "table=0, dl_type=0x0800, \
  nw_proto=17, tp_src=68, priority=$DHCP_PRIORITY, actions=controller"
