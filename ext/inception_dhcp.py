"""
Inception Cloud DHCP module
"""

from pox.core import core
from pox.lib import packet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()


class InceptionDhcp(object):
    """
    Inception Cloud DHCP module for handling DHCP packets
    """
    def __init__(self, inception):
        self.inception = inception
        # the switch to which DHCP server connects
        self.server_switch = None
        # the port of switch on which DHCP server connects
        self.server_port = None

    def update_server(self, switch, port):
        if self.server_port is not None and self.server_switch is not None:
            LOGGER.warning("More than one DHCP server!")
            return
        self.server_switch = switch
        self.server_port = port

    def handle(self, event):
        # process only if it is DHCP packet
        eth_packet = event.parsed
        if eth_packet.type != ethernet.IP_TYPE:
            return
        ip_packet = eth_packet.payload
        if ip_packet.protocol != ipv4.UDP_PROTOCOL:
            return
        udp_packet = ip_packet.payload
        if udp_packet.srcport not in [packet.dhcp.SERVER_PORT,
                                      packet.dhcp.CLIENT_PORT]:
            return

        LOGGER.info("Handle DHCP packet")
        dhcp_packet = udp_packet.payload
        LOGGER.debug("dhcp_packet=%s", dhcp_packet)
        if self.server_switch is None or self.server_port is None:
            LOGGER.warning("No DHCP server has been found!")
            return
        # A packet received from client. Find out the switch connected
        # to dhcp server and forward the packet
        if udp_packet.srcport == packet.dhcp.CLIENT_PORT:
            LOGGER.info("Forward DHCP message to DHCP server at switch=%s "
                        "port=%s", dpid_to_str(self.server_switch),
                        self.server_port)
            core.openflow.sendToDPID(self.server_switch, of.ofp_packet_out(
                    data=eth_packet.pack(),
                    action=of.ofp_action_output(port=self.server_port)))
        # A packet received from server. Find out the mac address of
        # the client and forward the packet to it.
        elif udp_packet.srcport == packet.dhcp.SERVER_PORT:
            LOGGER.info("Forward DHCP message to client=%s",
                        dhcp_packet.chaddr)
            dpid, port = self.inception.mac_to_dpid_port[dhcp_packet.chaddr]
            core.openflow.sendToDPID(dpid, of.ofp_packet_out(
                    data=eth_packet.pack(),
                    action=of.ofp_action_output(port=port)))
