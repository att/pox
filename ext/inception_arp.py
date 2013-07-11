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
# from pox.lib.addresses import EthAddr
# from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import time

LOGGER = core.getLogger()


# BOOTSTRAP_IP_TO_MAC_MAPPING = {
#     "10.251.0.1": "f6:3e:73:1b:71:b3"
# }

class ArpEntry(object):
    """
    Entry in arp table: (MAC, Virtual switch ID, Lifetime)
    """

    def __init__(self, mac=None, vsid=None, vsport=None, time=None):
        self.mac = mac
        self.vsid = vsid
        self.vsport = vsport
        self._time = time

    def is_expired(self, lifetime):
        return time.time() > (self._time + lifetime)

    def update_time(self, new_time):
        self._time = new_time


class InceptionArp(object):
    """
    Inception network controller component for handling ARP request
    """

    # Timeout for ARP entries
    arp_timeout = 60 * 2

    def __init__(self):
        core.openflow.addListeners(self)
        # Table arp_table stores mappings from IP address to MAC address
        self.arp_table = {}

        # Table mac_eth_table stores mappings from MAC addresses of bridges
        # to IP addresses of the rVM where the bridge resides.
        # The table is to facilitate topology built-up at controller
        # as construction of VXLan in OpenvSwitch only designates
        # remote IP rather than MAC address
        self.mac_eth_table = {}

        # Table peer_port_table stores mappings from MAC addresses and peer IP
        # to local port number.
        # The table is stored at controller for configuring switch's
        # forwarding table during ARP request
        self.peer_port_table = {}

        # for key, value in BOOTSTRAP_IP_TO_MAC_MAPPING.items():
        #     ipaddr = IPAddr(key)
        #     ethaddr = EthAddr(value)
        #     self.arp_table[ipaddr] = ethaddr

    def getIPByName(self, bridge_name):
        """
        Parse the bridge name to get the IP address of remote rVM
        to which the bridge builds a VXLan.
        """
        raw_tail_ip = bridge_name.split('_')[1]
        tail_ip = raw_tail_ip.replace('-', '.')
        peer_ip = "10.2." + tail_ip
        return peer_ip

    def _handle_ConnectionUp(self, event):
        # LOGGER.debug("Switch %s has come up.", dpid_to_str(event.dpid))
        dpid = event.dpid
        switch_features = event.ofp
        connection = event.connection
        sock = connection.sock
        remote_ip, port = sock.getpeername()

        # If the entry corresponding to the MAC already exists
        if dpid in self.mac_eth_table:
            LOGGER.info("MAC address: %s already exists", dpid_to_str(dpid))

        self.mac_eth_table[dpid] = remote_ip
        LOGGER.info("Mapping from: %s to: %s", dpid_to_str(dpid), remote_ip)

        # Collect port information.
        # Sift out the port connecting peers and store them in peer_port_table

        # LOGGER.info("Switch info: \n %s", switch_features.show())
        for port in switch_features.ports:
            port_name = port.name
            # Only store the port connecting remote rVM
            if port_name.count('_') == 1:
                peer_ip = self.getIPByName(port_name)
                self.peer_port_table[(dpid, peer_ip)] = port.port_no
                LOGGER.info("Port: from %s to %s via %s",\
                            dpid_to_str(dpid), peer_ip, port.port_no)

    def _handle_ConnectionDown(self, event):
        dpid = event.dpid
        # If the switch turns off connection,
        # delete its mapping from MAC address to eth0
        del self.mac_eth_table[dpid]
        LOGGER.info("Deleted: Mapping from: %s", dpid_to_str(dpid))
        # And delete all its port information
        for key in self.peer_port_table.keys():
            if dpid == key[0]:
                LOGGER.info("Deleted: Port: from %s via %s",\
                            dpid_to_str(dpid), self.peer_port_table[key])
                del self.peer_port_table[key]

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

            in_prot_src = arp_packet.protosrc
            in_prot_dst = arp_packet.protodst
            src_switch = event.dpid

            # Do src learning if possible
            if in_prot_src not in self.arp_table:
                self.arp_table[in_prot_src] = ArpEntry(arp_packet.hwsrc,
                                                       src_switch,
                                                       switch_inport,
                                                       time.time())
                LOGGER.info("Source learning: %s -> %s via switch: %s",
                            in_prot_src,
                            arp_packet.hwsrc,
                            dpid_to_str(src_switch))
            else:
                # Refresh the time if entry exists
                self.arp_table[in_prot_src].update_time(time.time())

            # Processing an ARP request
            if arp_packet.opcode == arp.REQUEST:
                LOGGER.info("This is ARP request from: %s querying: %s",
                            in_prot_src, in_prot_dst)

                if in_prot_dst in self.arp_table:
                    # If the entry expires, it is deleted (for now)
                    if self.arp_table[in_prot_dst].is_expired(time.time()):
                        del self.arp_table[in_prot_dst]
                        return

                    dst_mac = self.arp_table[in_prot_dst].mac
                    LOGGER.info("Fetch dpid: %s", dst_mac)

                    arp_reply = arp()
                    arp_reply.hwtype = arp_packet.hwtype
                    arp_reply.prototype = arp_packet.prototype
                    arp_reply.hwlen = arp_packet.hwlen
                    arp_reply.protolen = arp_packet.protolen
                    arp_reply.opcode = arp.REPLY
                    arp_reply.hwdst = arp_packet.hwsrc
                    arp_reply.protodst = in_prot_src
                    arp_reply.protosrc = in_prot_dst
                    arp_reply.hwsrc = dst_mac
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

                    msg_arp_reply = of.ofp_packet_out()
                    # I doubt whether the pack is needed here
                    msg_arp_reply.data = eth_reply.pack()
                    op_action = of.ofp_action_output(port=switch_inport)
                    msg_arp_reply.actions.append(op_action)
                    LOGGER.info("Packet out for switch to be sent on port: %i",
                                switch_inport)

                    # Meanwhile, set up flows on switches from src who issued
                    # ARP request to dst who is the target of the request
                    # This action should be prior to ARP reply to the inquirer
                    # First, set up a flow at src switch
                    dst_switch = self.arp_table[in_prot_dst].vsid
                    dst_ip = self.mac_eth_table[dst_switch]
                    src_fwd_port = self.peer_port_table[(src_switch, dst_ip)]

                    msg_src_flow = of.ofp_flow_mod()
                    # Priority might change
                    msg_src_flow.priority = 15
                    msg_src_flow.match.dl_dst = dst_mac
                    src_flow_action = of.ofp_action_output(port=src_fwd_port)
                    msg_src_flow.actions.append(src_flow_action)
                    event.connection.send(msg_src_flow)

                    # Next, set up a flow at dst switch
                    dst_fwd_port = self.arp_table[in_prot_dst].vsport

                    msg_dst_flow = of.ofp_flow_mod()
                    msg_dst_flow.priority = 15
                    msg_dst_flow.match.dl_dst = dst_mac
                    dst_flow_action = of.ofp_action_output(port=dst_fwd_port)
                    msg_dst_flow.actions.append(dst_flow_action)
                    core.openflow.sendToDPID(dst_switch, msg_dst_flow)

                    # Only after the flow table in set on the switches
                    # will the ARP reply be returned to the host
                    event.connection.send(msg_arp_reply)

                    return


def launch():
    """ Register the component to core"""
    core.registerNew(InceptionArp)
