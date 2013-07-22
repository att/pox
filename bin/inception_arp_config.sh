#!/bin/bash

# The bash is for configuring virtual switch(vs) on a virtual machine
# into intercepting all ARP broadcast requests through it, while all
# other traffic remains unaffected.

# THE BASH SHOULD BE RUN UNDER SUPER USER

# Connect the vs to the controller
ovs-vsctl set-controller obr1 tcp:10.2.184.75:6633

# Configure the controller to be out of band.  With controller "in
# band", Open vSwitch sets up special "hidden" flows to make sure that
# traffic can make it back and forth between OVS and the controller.
# These hidden flows are removed when controller is set "out of band"
ovs-vsctl set controller obr1 connection-mode=out-of-band

# Set fail-mode to secure so that when the connection to the
# controller is lost, the vs will not perform traditional L2/L3
# functionality
ovs-vsctl set bridge obr1 fail-mode=secure

# Add two flows to vs:
# Flow 1 intercepts all ARP broadcast requests
# Flow 2 orders all other traffic go as usual
ovs-ofctl add-flow obr1 table=0,dl_type=0x0806,dl_dst=ff:ff:ff:ff:ff:ff,priority=20,actions=controller
ovs-ofctl add-flow obr1 table=0,priority=10,actions=NORMAL
