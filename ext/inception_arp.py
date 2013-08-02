"""
ARP handling via SDN controller in Inception Cloud
"""

import time

from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
from pox import log
from pox.log import color
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()

IP_PREFIX = "10.2"

FWD_PRIORITY = 15

#timeout for ARP entries, in seconds
ARP_LIFESPAN = 60 * 15


class ArpEntry(object):
    """Arp entry"""

    def __init__(self, mac, dpid, vsport):
        """
        @param mac: MAC address
        @param dpid: virtual switch ID (dpid)
        @param vsport: virtual switch port
        """
        self.mac = mac
        self.dpid = dpid
        self.vsport = vsport
        self._timestamp = time.time()

    def is_expired(self):
        return time.time() > (self._timestamp + ARP_LIFESPAN)

    def refresh(self):
        self._timestamp = time.time()

    def __repr__(self):
        return "ArpEntry(mac=%s, dpid=%s, vsport=%s, timestamp=%s" % (
            self.mac, dpid_to_str(self.dpid), self.vsport,
            time.ctime(int(self._timestamp)))


class InceptionArp(object):
    """
    Inception network controller component for handling ARP request.
    """

    def __init__(self):
        """
        Controller stores three tables:

        ip_to_arp_table: records the mapping from IP address to MAC
        address (ArpEntry) of end hosts for address resolution.

        dpid_ip_to_port_table: records the neighboring relationship
        between switches. It is mapping from data path ID (dpid) of a
        switch and IP address of neighboring rVM to port number. Its
        semantics is that each entry stands for connection between
        switches via some specific port. VXLan, however, only stores
        information of IP address of rVM in which neighbor switches
        lies.  Rather than storing the mapping from dpid to dpid
        directly, we store mapping from dpid to IP address. With
        further look-up in dpid_to_ip_table, the dpid to dpid mapping
        can be retrieved.

        dpid_to_ip_table: records the mapping from data path ID (dpid)
        of a switch to IP address of the rVM where it resides. This
        table is to facilitate the look-up of dpid_ip_to_port_table.
        """
        core.openflow.addListeners(self)
        # IP address -> ArpEntry
        self.ip_to_arp_table = {}
        # dpid -> IP address
        self.dpid_to_ip_table = {}
        # (dpid, IP address) -> port
        self.dpid_ip_to_port_table = {}
        # src_mac -> (packet_in event)
        self.mac_to_event_table = {}

    def _handle_ConnectionUp(self, event):
        """
        Handle when a switch is connected
        """
        switch_id = event.dpid
        switch_features = event.ofp
        connection = event.connection
        sock = connection.sock
        ip, port = sock.getpeername()

        # If the entry corresponding to the MAC already exists
        if switch_id in self.dpid_to_ip_table:
            LOGGER.info("Switch=%s is already connected",
                        dpid_to_str(switch_id))
        else:
            self.dpid_to_ip_table[switch_id] = ip
            LOGGER.info("Add: dpid=%s -> ip=%s", dpid_to_str(switch_id), ip)

        # Collect port information.  Sift out ports connecting peer
        # switches and store them in dpid_ip_to_port_table
        for port in switch_features.ports:
            # FIXME(changbl): Parse the port name to get the IP
            # address of remote rVM to which the bridge builds a
            # VXLAN. E.g., obr1_184-53 => IP_PREFIX.184.53. Only store
            # the port connecting remote rVM.
            if port.name.startswith('obr') and '_' in port.name:
                _, ip_suffix = port.name.split('_')
                ip_suffix = ip_suffix.replace('-', '.')
                peer_ip = '.'.join((IP_PREFIX, ip_suffix))
                self.dpid_ip_to_port_table[(switch_id, peer_ip)] = port.port_no
                LOGGER.info("Add: (dpid=%s, peer_ip=%s) -> port=%s",
                            dpid_to_str(switch_id), peer_ip, port.port_no)

    def _handle_ConnectionDown(self, event):
        """
        Handle when a switch turns off connection
        """
        switch_id = event.dpid
        # Delete switch's mapping from MAC address to remote IP address
        LOGGER.info("Del: switch=%s -> ip=%s", dpid_to_str(switch_id),
                    self.dpid_to_ip_table[switch_id])
        del self.dpid_to_ip_table[switch_id]
        # Delete all its port information
        for key in self.dpid_ip_to_port_table.keys():
            (dpid, ip) = key
            if switch_id == dpid:
                LOGGER.info("Del: (dpid=%s, peer_ip=%s) -> port=%s",
                            dpid_to_str(dpid), ip,
                            self.dpid_ip_to_port_table[key])
                del self.dpid_ip_to_port_table[key]

    def _handle_PacketIn(self, event):
        """
        Handle when a packet is received
        """
        switch_id = event.dpid
        pkt_in_port = event.port
        eth_packet = event.parsed

        # If packet is not parsed properly, alert
        if not eth_packet.parsed:
            LOGGER.warning("Unparsable packet")
            return

        # The ethernet packet carries ARP
        if eth_packet.type == ethernet.ARP_TYPE:
            LOGGER.info("Ethernet ARP packet received")
            arp_packet = eth_packet.payload
            # Refresh time stamp if entry exists
            if arp_packet.protosrc in self.ip_to_arp_table:
                self.ip_to_arp_table[arp_packet.protosrc].refresh()
                LOGGER.info("Ip-mac mapping for %s refreshed",
                            arp_packet.protosrc)
            # Otherwise, do source learning
            else:
                arp_entry = ArpEntry(arp_packet.hwsrc, switch_id, pkt_in_port)
                self.ip_to_arp_table[arp_packet.protosrc] = arp_entry
                LOGGER.info("Add: source learning: %s -> %s",
                            arp_packet.protosrc, arp_entry)

            # Process ARP reply
            # Reply to ARP request buffered in the buffer list
            if arp_packet.opcode == arp.REPLY:
                LOGGER.info("ARP reply from %s", arp_packet.protosrc)
                if arp_packet.hwdst in self.mac_to_event_table.keys():
                    event_to_reply = self.mac_to_event_table[arp_packet.hwdst]
                    event_to_reply.connection.send(of.ofp_packet_out(
                            data=eth_packet.pack(),
                            action=of.ofp_action_output(
                                port=event_to_reply.port)))
                    del self.mac_to_event_table[arp_packet.hwdst]
                    LOGGER.info("Forward ARP reply from %s to %s in buffer",
                                arp_packet.protosrc, arp_packet.protodst)

            # Process ARP request
            if arp_packet.opcode == arp.REQUEST:
                LOGGER.info("ARP request: %s query: %s",
                            arp_packet.protosrc, arp_packet.protodst)
                if arp_packet.protodst not in self.ip_to_arp_table:
                    # Entry not found, store the event and flood request
                    LOGGER.info("Entry for %s not found, buffer request",
                                arp_packet.protodst)
                    self.mac_to_event_table[arp_packet.hwsrc] = event
                    for conn in core.openflow.connections:
                        conn_ports = conn.features.ports
                        # Sift out ports connecting to hosts but vxlan peers
                        host_ports = [port.port_no for port in conn_ports
                                      if port.port_no not in
                                      self.dpid_ip_to_port_table.values()]
                        actions_out_ports = [of.ofp_action_output(port=hport)
                                             for hport in host_ports]
                        core.openflow.sendToDPID(conn.dpid, of.ofp_packet_out(
                                data=eth_packet.pack(),
                                action=actions_out_ports))
                        LOGGER.info("Broadcast request")
                elif self.ip_to_arp_table[arp_packet.protodst].is_expired():
                    # If entry expires, send the request unicastly to dst
                    LOGGER.info("Entry expires, unicast to %s",
                                arp_packet.hwdst)
                    unicast_dpid = (self.ip_to_arp_table[arp_packet.protodst].
                                   dpid)
                    unicast_port = (self.ip_to_arp_table[arp_packet.protodst].
                                    vsport)
                    core.openflow.sendToDPID(unicast_dpid, of.ofp_packet_out(
                            data=eth_packet.pack(),
                            action=of.ofp_action_output(port=unicast_port)))
                else:
                    dst_mac = self.ip_to_arp_table[arp_packet.protodst].mac
                    LOGGER.info("Hit: dst_ip=%s, dst_mac=%s",
                                arp_packet.protodst, dst_mac)

                    # Prepare to setup two flows
                    peer_switch_id = (self.ip_to_arp_table[arp_packet.protodst]
                                      .dpid)
                    peer_ip = self.dpid_to_ip_table[peer_switch_id]
                    fwd_port = self.dpid_ip_to_port_table[(switch_id, peer_ip)]
                    peer_fwd_port = (self.ip_to_arp_table[arp_packet.protodst]
                                     .vsport)
                    # The first flow at switch
                    event.connection.send(of.ofp_flow_mod(
                        match=of.ofp_match(dl_dst=dst_mac),
                        action=of.ofp_action_output(port=fwd_port),
                        priority=FWD_PRIORITY))
                    LOGGER.info("Setup forwarding flow on switch=%s for "
                                "dst_mac=%s", dpid_to_str(switch_id), dst_mac)
                    # The second flow at peer switch
                    core.openflow.sendToDPID(peer_switch_id, of.ofp_flow_mod(
                        match=of.ofp_match(dl_dst=dst_mac),
                        action=of.ofp_action_output(port=peer_fwd_port),
                        priority=FWD_PRIORITY))
                    LOGGER.info("Setup forwarding flow on switch=%s for "
                                "dst_mac=%s", dpid_to_str(peer_switch_id),
                                dst_mac)

                    # construct ARP reply packet and send it to the host
                    arp_reply = arp(opcode=arp.REPLY,
                                    hwdst=arp_packet.hwsrc,
                                    hwsrc=dst_mac,
                                    protodst=arp_packet.protosrc,
                                    protosrc=arp_packet.protodst)
                    LOGGER.info("ARP reply from controller to %s \
                                on behalf of %s",
                                arp_reply.protodst, arp_reply.protosrc)
                    eth_reply = ethernet(type=ethernet.ARP_TYPE,
                                         src=arp_reply.hwsrc,
                                         dst=arp_reply.hwdst)
                    eth_reply.payload = arp_reply
                    event.connection.send(of.ofp_packet_out(
                        data=eth_reply.pack(),
                        action=of.ofp_action_output(port=pkt_in_port)))
                    LOGGER.info("Send ARP reply to host=%s on port: %s",
                                arp_reply.protodst, pkt_in_port)


def launch():
    """ Register the component to core"""
    color.launch()
    log.launch(format="%(asctime)s - %(name)s - %(levelname)s - "
               "%(threadName)s - %(message)s")
    core.registerNew(InceptionArp)
    LOGGER.info("InceptionArp is running...")
