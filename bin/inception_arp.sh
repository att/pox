#!/bin/bash

BRIDGE_NAME=obr1
ARP_PRIORITY=20

# Intercepts all ARP packets and send them to the controller
sudo ovs-ofctl add-flow $BRIDGE_NAME "table=0, dl_type=0x0806, \
  priority=$ARP_PRIORITY, actions=controller"
