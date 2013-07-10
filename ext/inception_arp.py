 # This file describes centralized handling of ARP protocol of a controller
 # in inception cloud.

"""
The controller connects to all open vswitches (ovs), listens to arp request
packets, processes them, and reply on behalf of the host in inquiry.

Data structure in controller:
A table storing IP to MAC address mappings.

Packet processing:
1. On receiving an ARP request packet, extracts the destination IP.
2. Search the table for corresponding MAC address.
3. If MAC address found, constructs an ARP reply packet including MAC address.
   Sends out the reply packet to the ovs from which ARP request was received.
4. If MAC address is not found, do nothing.

"""
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib import revent

import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class ArpTable(object):
    """
    ArpTable stores mappings from IP address to MAC address.
    The table is maintained as a dictionary.
    """
    def __init__(self):
        self.table = {}

    def Insert(self, key, value):
        self.table[key] = value
        return

    def Delete(self, key):
        del self.table[key]
        return

    def Find(self, key):
        return self.table[key]

    def Exists(self, key):
        if key in self.table:
            return True
        return False


class IcpArp(object):
    """
    IcpArp is the component for handling ARP request
    """
    def __init__(self):
        core.openflow.addListeners(self)
        self.icp_arp_table = ArpTable()
        # Hard code the mapping of gateway for test
        self.icp_arp_table.Insert(IPAddr("10.251.0.1"),
                                  EthAddr("f6:3e:73:1b:71:b3"))

    def _handle_ConnectionUp(self, event):
        log.debug("Switch %s has come up.", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        switch_inport = event.port
        eth_packet = event.parsed
        # If packet is not parsed properly, alert
        if not eth_packet.parsed:
            log.warning("Unparsed packet")
            return

        # The ethernet packet carries an ARP packet
        if isinstance(eth_packet.next, arp):
            log.info("Ethernet packet received from: %s to: %s",
                     eth_packet.src, eth_packet.dst)
            arp_packet = eth_packet.next
        # Do src learning if possible
            if not self.icp_arp_table.Exists(arp_packet.protosrc):
                self.icp_arp_table.Insert(arp_packet.protosrc,
                                          arp_packet.hwsrc)
                log.info("Source learning: %s -> %s",
                         arp_packet.protosrc, arp_packet.hwsrc)

            if arp_packet.opcode == arp.REQUEST:
                log.info("This is ARP request from: %s querying: %s",
                         arp_packet.protosrc, arp_packet.protodst)

                if self.icp_arp_table.Exists(arp_packet.protodst):
                    # log.info("The mapping is stored in the table")
                    arp_reply = arp()
                    arp_reply.hwtype = arp_packet.hwtype
                    arp_reply.prototype = arp_packet.prototype
                    arp_reply.hwlen = arp_packet.hwlen
                    arp_reply.protolen = arp_packet.protolen
                    arp_reply.opcode = arp.REPLY
                    arp_reply.hwdst = arp_packet.hwsrc
                    arp_reply.protodst = arp_packet.protosrc
                    arp_reply.protosrc = arp_packet.protodst
                    rp_hwsrc = arp_packet.protodst
                    arp_reply.hwsrc = self.icp_arp_table.Find(rp_hwsrc)
                    log.info("ARP reply answering: %s with MAC of: %s",
                             arp_reply.protodst, arp_reply.protosrc)

                    # Currently the src address of Ethernet packet
                    # is set to the destination of query.
                    # I doubt whether it should be the MAC of controller
                    eth_reply = ethernet(type=ethernet.ARP_TYPE,
                                         src=arp_reply.hwsrc,
                                         dst=arp_reply.hwdst)
                    eth_reply.set_payload(arp_reply)
                    log.info("Ethernet packet generated")

                    msg = of.ofp_packet_out()
                    # I doubt whether the pack is needed here
                    msg.data = eth_reply.pack()
                    op_action = of.ofp_action_output(port=switch_inport)
                    msg.actions.append(op_action)
                    event.connection.send(msg)
                    log.info("Packet out for switch to be sent on port: %i",
                             switch_inport)
                    return


def launch():
    core.registerNew(IcpArp)
