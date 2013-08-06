"""
Inception Cloud ARP module
"""

import time

from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()

#timeout for ARP entries, in seconds
ARP_LIFESPAN = 60 * 15


class ArpEntry(object):
    """Arp entry"""

    def __init__(self, mac, dpid, port):
        """
        @param mac: MAC address
        @param dpid: virtual switch ID (dpid)
        @param port: virtual switch port
        """
        self.mac = mac
        self.dpid = dpid
        self.port = port
        self._timestamp = time.time()

    def is_expired(self):
        return time.time() > (self._timestamp + ARP_LIFESPAN)

    def refresh(self):
        self._timestamp = time.time()

    def __repr__(self):
        return "ArpEntry(mac=%s, dpid=%s, port=%s, timestamp=%s" % (
            self.mac, dpid_to_str(self.dpid), self.port,
            time.ctime(int(self._timestamp)))


class InceptionArp(object):
    """
    Inception cloud ARP module for handling ARP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # IP address -> ArpEntry: records the mapping from IP address
        # to MAC address (ArpEntry) of end hosts for address
        # resolution.
        self.ip_to_arp = {}
        # src_mac -> (packet_in event): records unanwsered ARP request
        # events
        self.mac_to_event = {}

    def handle(self, event):
        LOGGER.info("Handle ARP packet")
        eth_packet = event.parsed
        arp_packet = eth_packet.payload

        # do source leraning
        self._do_source_learning(event)
        # Process ARP request
        if arp_packet.opcode == arp.REQUEST:
            self._hanle_arp_request(event)
        # Process ARP reply
        elif arp_packet.opcode == arp.REPLY:
            self._handle_arp_reply(event)

    def _do_source_learning(self, event):
        """
        Learn the IP <=> MAC mapping from a received ARP packet
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        # Refresh time stamp if entry exists
        if arp_packet.protosrc in self.ip_to_arp:
            self.ip_to_arp[arp_packet.protosrc].refresh()
            LOGGER.info("IP-MAC mapping for %s refreshed",
                        arp_packet.protosrc)
        # Otherwise, add new entry
        else:
            arp_entry = ArpEntry(arp_packet.hwsrc, event.dpid, event.port)
            self.ip_to_arp[arp_packet.protosrc] = arp_entry
            LOGGER.info("Add: source learning: %s -> %s",
                        arp_packet.protosrc, arp_entry)

    def _hanle_arp_request(self, event):
        """
        Process ARP request packet
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        LOGGER.info("ARP request: %s query %s", arp_packet.protosrc,
                    arp_packet.protodst)
        # If entry not found, store the event and broadcast request
        if arp_packet.protodst not in self.ip_to_arp:
            LOGGER.info("Entry for %s not found, buffer and broadcast request",
                        arp_packet.protodst)
            self.mac_to_event[arp_packet.hwsrc] = event
            for conn in core.openflow.connections:
                conn_ports = conn.features.ports
                # Sift out ports connecting to hosts but vxlan peers
                host_ports = [port.port_no for port in conn_ports
                              if port.port_no not in
                              self.inception.dpid_ip_to_port.values()]
                actions_out_ports = [of.ofp_action_output(port=port)
                                     for port in host_ports]
                core.openflow.sendToDPID(conn.dpid, of.ofp_packet_out(
                    data=eth_packet.pack(),
                    action=actions_out_ports))
        # If entry expires, send the request unicastly to dst
        elif self.ip_to_arp[arp_packet.protodst].is_expired():
            LOGGER.info("Entry expires, unicast to %s", arp_packet.hwdst)
            unicast_dpid = self.ip_to_arp[arp_packet.protodst].dpid
            unicast_port = self.ip_to_arp[arp_packet.protodst].port
            core.openflow.sendToDPID(unicast_dpid, of.ofp_packet_out(
                data=eth_packet.pack(),
                action=of.ofp_action_output(port=unicast_port)))
        # Entry exists and is fresh
        else:
            # setup data forwrading flows
            dst_mac = self.ip_to_arp[arp_packet.protodst].mac
            switch_id = event.dpid
            peer_switch_id = self.ip_to_arp[arp_packet.protodst].dpid
            peer_ip = self.inception.dpid_to_ip[peer_switch_id]
            fwd_port = self.inception.dpid_ip_to_port[(switch_id, peer_ip)]
            peer_fwd_port = self.ip_to_arp[arp_packet.protodst].port
            self.inception.setup_fwd_flows(dst_mac, switch_id, fwd_port,
                                           peer_switch_id, peer_fwd_port)
            # construct ARP reply packet and send it to the host
            LOGGER.info("Hit: dst_ip=%s, dst_mac=%s", arp_packet.protodst,
                        dst_mac)
            arp_reply = arp(opcode=arp.REPLY,
                            hwdst=arp_packet.hwsrc,
                            hwsrc=dst_mac,
                            protodst=arp_packet.protosrc,
                            protosrc=arp_packet.protodst)
            eth_reply = ethernet(type=ethernet.ARP_TYPE,
                                 src=arp_reply.hwsrc,
                                 dst=arp_reply.hwdst)
            eth_reply.payload = arp_reply
            event.connection.send(of.ofp_packet_out(
                data=eth_reply.pack(),
                action=of.ofp_action_output(port=event.port)))
            LOGGER.info("Send ARP reply to host=%s on port=%s on behalf of %s",
                        arp_reply.protodst, event.port, arp_reply.protosrc)

    def _handle_arp_reply(self, event):
        """
        Process ARP reply packet
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        LOGGER.info("ARP reply: %s answer %s", arp_packet.protosrc,
                    arp_packet.protodst)
        # if prevoiusly someone sent a ARP request for the destination
        if arp_packet.hwdst in self.mac_to_event.keys():
            event_to_reply = self.mac_to_event[arp_packet.hwdst]
            # setup data forwarding flows
            dst_mac = arp_packet.hwsrc
            switch_id = event_to_reply.dpid
            peer_switch_id = event.dpid
            peer_ip = self.inception.dpid_to_ip[peer_switch_id]
            fwd_port = self.inception.dpid_ip_to_port[(switch_id, peer_ip)]
            peer_fwd_port = event.port
            self.inception.setup_fwd_flows(dst_mac, switch_id, fwd_port,
                                           peer_switch_id, peer_fwd_port)
            # forwrad ARP reply
            event_to_reply.connection.send(of.ofp_packet_out(
                data=eth_packet.pack(),
                action=of.ofp_action_output(port=event_to_reply.port)))
            del self.mac_to_event[arp_packet.hwdst]
            LOGGER.info("Forward ARP reply from %s to %s in buffer",
                        arp_packet.protosrc, arp_packet.protodst)
