"""
Inception Cloud ARP module
"""

from pox.core import core
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
from ext import priority

LOGGER = core.getLogger()


class InceptionArp(object):
    """
    Inception Cloud ARP module for handling ARP packets
    """

    def __init__(self, inception):
        self.inception = inception
        # IP address -> MAC address: mapping from IP address to MAC address
        # of end hosts for address resolution
        self.ip_to_mac = {}

    def handle(self, event):
        # process only if it is ARP packet
        eth_packet = event.parsed
        if eth_packet.type != ethernet.ARP_TYPE:
            return

        LOGGER.info("Handle ARP packet")
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
        Learn IP => MAC mapping from a received ARP packet, update
        self.ip_to_mac table
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        if arp_packet.protosrc not in self.ip_to_mac:
            self.ip_to_mac[arp_packet.protosrc] = arp_packet.hwsrc
            LOGGER.info("Learn: ip=%s => mac=%s",
                        arp_packet.protosrc, arp_packet.hwsrc)

    def _hanle_arp_request(self, event):
        """
        Process ARP request packet
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        LOGGER.info("ARP request: ip=%s query ip=%s", arp_packet.protosrc,
                    arp_packet.protodst)
        # If entry not found, store the event and broadcast request
        if arp_packet.protodst not in self.ip_to_mac:
            LOGGER.info("Entry for %s not found, buffer and broadcast request",
                        arp_packet.protodst)
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
        # Entry exists
        else:
            # setup data forwrading flows
            dst_mac = self.ip_to_mac[arp_packet.protodst]
            switch_id = event.dpid
            self._setup_data_fwd_flows(switch_id, dst_mac)
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
            LOGGER.info("Send ARP reply to host=%s on port=%s on behalf of "
                        "ip=%s", arp_reply.protodst, event.port,
                        arp_reply.protosrc)

    def _handle_arp_reply(self, event):
        """
        Process ARP reply packet
        """
        eth_packet = event.parsed
        arp_packet = eth_packet.payload
        LOGGER.info("ARP reply: ip=%s answer ip=%s", arp_packet.protosrc,
                    arp_packet.protodst)
        # if I know to whom to forward back this ARP reply
        if arp_packet.hwdst in self.inception.mac_to_dpid_port:
            switch_id, port = self.inception.mac_to_dpid_port[arp_packet.hwdst]
            # setup data forwarding flows
            dst_mac = arp_packet.hwsrc
            self._setup_data_fwd_flows(switch_id, dst_mac)
            # forwrad ARP reply
            core.openflow.sendToDPID(switch_id, of.ofp_packet_out(
                data=eth_packet.pack(),
                action=of.ofp_action_output(port=port)))
            LOGGER.info("Forward ARP reply from ip=%s to ip=%s in buffer",
                        arp_packet.protosrc, arp_packet.protodst)

    def _setup_data_fwd_flows(self, switch_id, dst_mac):
        """
        Given a switch and dst_mac address, setup two flows for data forwarding
        on the switch and its peer switch if the two are not the same. If the
        same, setup only one flow.
        """
        (peer_switch_id, peer_fwd_port) = (self.inception.
                                           mac_to_dpid_port[dst_mac])
        peer_ip = self.inception.dpid_to_ip[peer_switch_id]
        # two switches are different, setup a first flow at switch
        if switch_id != peer_switch_id:
            fwd_port = self.inception.dpid_ip_to_port[(switch_id, peer_ip)]
            core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
                match=of.ofp_match(dl_dst=dst_mac),
                action=of.ofp_action_output(port=fwd_port),
                priority=priority.DATA_FWD))
            LOGGER.info("Setup forward flow on switch=%s for dst_mac=%s",
                        dpid_to_str(switch_id), dst_mac)
        # Setup flow at the peer switch
        core.openflow.sendToDPID(peer_switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_dst=dst_mac),
            action=of.ofp_action_output(port=peer_fwd_port),
            priority=priority.DATA_FWD))
        LOGGER.info("Setup forward flow on switch=%s for dst_mac=%s",
                    dpid_to_str(peer_switch_id), dst_mac)
