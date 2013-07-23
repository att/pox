"""ARP handling via SDN controller in Inception Cloud
"""

import time

from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()

IP_PREFIX = "10.2."

FWD_PRIO = 15

#timeout for ARP entries, in seconds
ARP_LIFESPAN = 120


class ArpEntry(object):
    """Arp entry"""

    def __init__(self, mac, vsid, vsport):
        """
        @param mac: MAC address
        @param vsid: virtual switch ID
        @param vsport: virtual switch port
        """
        self.mac = mac
        self.vsid = vsid
        self.vsport = vsport
        self._timestamp = time.time()

    def is_expired(self):
        return time.time() > (self._timestamp + ARP_LIFESPAN)

    def refresh(self):
        self._timestamp = time.time()


class InceptionArp(object):
    """
    Inception network controller component for handling ARP request.
    The controller connects to all switches and process ARP requests
    on behalf of them.
    """

    def __init__(self):
        """
        The controller stores three tables:

        ip_to_arp_table: records the mapping from IP address to MAC
        address of end hosts for address resolution. In addition, it
        associates each entry with switch ID, port number and time
        columns, respectively representing the ID of the switch host is
        connected to, the port of the switch connected and lifespan of the
        entry for timeout.

        dpid_ip_to_port_table: records the neighboring relationship
        between switches. It is mapping from data path ID(dpid) of a
        switch and IP address of neighboring rVM to port number. Its
        semantics is that each entry stands for connection between
        switches via some specific port. VXLan, however, only stores
        information of IP address of rVM in which neighbor switches lies.
        Rather than storing the mapping from dpid to dpid directly, we
        store mapping from dpid to IP address. With further look-up in
        dpid_to_ip_table, the dpid to dpid mapping can be retrieved.

        dpid_to_ip_table: records the mapping from data path ID(dpid) of a
        switch to IP address of the rVM where it resides. This table is to
        facilitate the look-up of dpid_ip_to_port_table. As
        dpid_ip_to_port_table only stores mapping from dpid to IP address
        of rVM, while during forwarding, the controller only receives the
        dpid's of switches. The dpid_to_ip_table will enable controller to
        convert the destination dpid to its corresponding IP address of
        rVM, thus enabling look-up of port number in table
        dpid_ip_to_port_table.
        """
        core.openflow.addListeners(self)
        # IP address -> ArpEntry
        self.ip_to_arp_table = {}
        # dpid -> IP address
        self.dpid_to_ip_table = {}
        # (dpid, IP address) -> port
        self.dpid_ip_to_port_table = {}

    def get_ip_by_port(self, port_name):
        """
        Parse the port name to get the IP address of remote rVM
        to which the bridge builds a VXLan.
        """
        raw_tail_ip = port_name.split('_')[1]
        tail_ip = raw_tail_ip.replace('-', '.')
        peer_ip = IP_PREFIX + tail_ip
        return peer_ip

    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        switch_features = event.ofp
        connection = event.connection
        sock = connection.sock
        remote_ip, port = sock.getpeername()

        # If the entry corresponding to the MAC already exists
        if dpid in self.dpid_to_ip_table:
            LOGGER.info("MAC address: %s already exists", dpid_to_str(dpid))

        self.dpid_to_ip_table[dpid] = remote_ip
        LOGGER.info("Mapping from: %s to: %s", dpid_to_str(dpid), remote_ip)

        # Collect port information.  Sift out ports connecting peer
        # switches and store them in dpid_ip_to_port_table
        for port in switch_features.ports:
            port_name = port.name
            # Only store the port connecting remote rVM
            if port_name.count('_') == 1:
                peer_ip = self.get_ip_by_port(port_name)
                self.dpid_ip_to_port_table[(dpid, peer_ip)] = port.port_no
                LOGGER.info("Port: from %s to %s via %s",
                            dpid_to_str(dpid), peer_ip, port.port_no)

    def _handle_ConnectionDown(self, event):
        dpid = event.dpid
        # If the switch turns off connection, delete its mapping from
        # MAC address to remote IP address
        del self.dpid_to_ip_table[dpid]
        LOGGER.info("Deleted: Mapping from: %s", dpid_to_str(dpid))
        # And delete all its port information
        for key in self.dpid_ip_to_port_table.keys():
            if dpid == key[0]:
                LOGGER.info("Deleted: Port: from %s via %s",
                            dpid_to_str(dpid), self.dpid_ip_to_port_table[key])
                del self.dpid_ip_to_port_table[key]

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

            # Do source learning if possible
            if in_prot_src not in self.ip_to_arp_table:
                self.ip_to_arp_table[in_prot_src] = ArpEntry(arp_packet.hwsrc,
                                                             src_switch,
                                                             switch_inport)
                LOGGER.info("Source learning: %s -> %s via switch: %s",
                            in_prot_src,
                            arp_packet.hwsrc,
                            dpid_to_str(src_switch))
            else:
                # Refresh time stamp if entry exists
                self.ip_to_arp_table[in_prot_src].refresh()

            # Processing an ARP request
            if arp_packet.opcode == arp.REQUEST:
                LOGGER.info("This is ARP request from: %s querying: %s",
                            in_prot_src, in_prot_dst)

                if in_prot_dst in self.ip_to_arp_table:
                    # If the entry expires, delete (for now)
                    if self.ip_to_arp_table[in_prot_dst].is_expired():
                        del self.ip_to_arp_table[in_prot_dst]
                        return

                    dst_mac = self.ip_to_arp_table[in_prot_dst].mac
                    LOGGER.info("Fetch dpid: %s", dst_mac)

                    arp_reply = arp(hwtype=arp_packet.hwtype,
                                    prototype=arp_packet.prototype,
                                    hwlen=arp_packet.hwlen,
                                    protolen=arp_packet.protolen,
                                    opcode=arp.REPLY,
                                    hwdst=arp_packet.hwsrc,
                                    hwsrc=dst_mac,
                                    protodst=in_prot_src,
                                    protosrc=in_prot_dst)
                    LOGGER.info("ARP reply answering: %s with MAC of: %s",
                                arp_reply.protodst, arp_reply.protosrc)

                    # Currently the source address of Ethernet packet
                    # is set to the destination of query.  I doubt
                    # whether it should be the MAC of controller
                    eth_reply = ethernet(type=ethernet.ARP_TYPE,
                                         src=arp_reply.hwsrc,
                                         dst=arp_reply.hwdst)
                    eth_reply.set_payload(arp_reply)
                    LOGGER.info("Ethernet packet generated")

                    msg_arp_reply = of.ofp_packet_out()
                    msg_arp_reply.data = eth_reply.pack()
                    op_action = of.ofp_action_output(port=switch_inport)
                    msg_arp_reply.actions.append(op_action)
                    LOGGER.info("Packet out for switch to be sent on port: %i",
                                switch_inport)

                    # Set up flows on source switch and destination
                    # switch This should be prior to ARP reply to the
                    # inquirer

                    # First, set up a flow at src switch
                    dst_switch = self.ip_to_arp_table[in_prot_dst].vsid
                    dst_ip = self.dpid_to_ip_table[dst_switch]
                    src_fwd_port = self.dpid_ip_to_port_table[(src_switch,
                                                               dst_ip)]

                    msg_src_flow = of.ofp_flow_mod()
                    msg_src_flow.priority = FWD_PRIO
                    msg_src_flow.match.dl_dst = dst_mac
                    src_flow_action = of.ofp_action_output(port=src_fwd_port)
                    msg_src_flow.actions.append(src_flow_action)
                    event.connection.send(msg_src_flow)

                    # Next, set up a flow at dst switch
                    dst_fwd_port = self.ip_to_arp_table[in_prot_dst].vsport

                    msg_dst_flow = of.ofp_flow_mod()
                    msg_dst_flow.priority = FWD_PRIO
                    msg_dst_flow.match.dl_dst = dst_mac
                    dst_flow_action = of.ofp_action_output(port=dst_fwd_port)
                    msg_dst_flow.actions.append(dst_flow_action)
                    core.openflow.sendToDPID(dst_switch, msg_dst_flow)

                    # Only after the flow table is set on the switches
                    # will the ARP reply be returned to the host
                    event.connection.send(msg_arp_reply)
                    return


def launch():
    """ Register the component to core"""
    core.registerNew(InceptionArp)
