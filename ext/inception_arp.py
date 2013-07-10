# This file describes centralized handling of ARP protocol of a controller
# in inception cloud.

"""
The controller connects to all open vswitches (ovs), listens to arp
request packets, processes them, and reply on behalf of the host in
inquiry.

Data structure in controller:

A table storing IP to MAC address mappings.

Packet processing:

1. On receiving an ARP request packet, extracts the destination IP.

2. Search the table for corresponding MAC address.

3. If MAC address found, constructs an ARP reply packet including MAC
   address.  Sends out the reply packet to the ovs from which ARP
   request was received.

4. If MAC address is not found, do nothing.
"""

from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()

BOOTSTRAP_IP_TO_MAC_MAPPING = {
    "10.251.0.1": "f6:3e:73:1b:71:b3"
}


class InceptionArp(object):
    """
    Inception network controller component for handling ARP request
    """
    def __init__(self):
        core.openflow.addListeners(self)
        # stores mappings from IP address to MAC address
        self.arp_table = {}
        for key, value in BOOTSTRAP_IP_TO_MAC_MAPPING.items():
            ipaddr = IPAddr(key)
            ethaddr = EthAddr(value)
            self.arp_table[ipaddr] = ethaddr

    def _handle_ConnectionUp(self, event):
        LOGGER.debug("Switch %s has come up.", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        switch_inport = event.port
        eth_packet = event.parsed
        # If packet is not parsed properly, alert
        if not eth_packet.parsed:
            LOGGER.warning("Unparsed packet")
            return

        # The ethernet packet carries an ARP packet
        if isinstance(eth_packet.next, arp):
            LOGGER.info("Ethernet packet received from: %s to: %s",
                        eth_packet.src, eth_packet.dst)
            arp_packet = eth_packet.next
            # Do src learning if possible
            if arp_packet.protosrc not in self.arp_table:
                self.arp_table[arp_packet.protosrc] = arp_packet.hwsrc
                LOGGER.info("Source learning: %s -> %s",
                            arp_packet.protosrc, arp_packet.hwsrc)

            if arp_packet.opcode == arp.REQUEST:
                LOGGER.info("This is ARP request from: %s querying: %s",
                            arp_packet.protosrc, arp_packet.protodst)

                if arp_packet.protodst in self.arp_table:
                    # LOGGER.info("The mapping is stored in the table")
                    arp_reply = arp()
                    arp_reply.hwtype = arp_packet.hwtype
                    arp_reply.prototype = arp_packet.prototype
                    arp_reply.hwlen = arp_packet.hwlen
                    arp_reply.protolen = arp_packet.protolen
                    arp_reply.opcode = arp.REPLY
                    arp_reply.hwdst = arp_packet.hwsrc
                    arp_reply.protodst = arp_packet.protosrc
                    arp_reply.protosrc = arp_packet.protodst
                    arp_reply.hwsrc = self.arp_table[arp_packet.protodst]
                    LOGGER.info("ARP reply answering: %s with MAC of: %s",
                                arp_reply.protodst, arp_reply.protosrc)

                    # Currently the src address of Ethernet packet is
                    # set to the destination of query.  I doubt
                    # whether it should be the MAC of controller
                    eth_reply = ethernet(type=ethernet.ARP_TYPE,
                                         src=arp_reply.hwsrc,
                                         dst=arp_reply.hwdst)
                    eth_reply.set_payload(arp_reply)
                    LOGGER.info("Ethernet packet generated")

                    msg = of.ofp_packet_out()
                    # I doubt whether the pack is needed here
                    msg.data = eth_reply.pack()
                    op_action = of.ofp_action_output(port=switch_inport)
                    msg.actions.append(op_action)
                    event.connection.send(msg)
                    LOGGER.info("Packet out for switch to be sent on port: %i",
                                switch_inport)
                    return


def launch():
    """TODO: doc"""
    core.registerNew(InceptionArp)
