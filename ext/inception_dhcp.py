"""
Inception Cloud DHCP module
"""

from pox.core import core
from pox.lib import packet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet
import pox.openflow.libopenflow_01 as of

LOGGER = core.getLogger()

DHCP_SERVER = "10.2.184.75"


class InceptionDhcp(object):
    """
    Inception Cloud DHCP module for handling DHCP packets
    """
    def __init__(self, inception):
        """
        @param server_switch: the switch to which DHCP server connects
        @param server_switch: the port of switch on which DHCP server connects
        """
        self.inception = inception
        self.server_switch = None
        self.server_port = None

    def update(self, switch, port):
        self.server_switch = switch
        self.server_port = port

    def handle(self, event):
        # process only if it is DHCP packet
        eth_packet = event.parsed
        if eth_packet.type != ethernet.IP_TYPE:
            return
        ip_packet = eth_packet.payload
        LOGGER.debug("ip_packet=%s", ip_packet)
        if ip_packet.protocol != ipv4.UDP_PROTOCOL:
            return
        udp_packet = ip_packet.payload
        LOGGER.debug("udp_packet=%s", udp_packet)
        if udp_packet.srcport not in [packet.dhcp.SERVER_PORT,
                                      packet.dhcp.CLIENT_PORT]:
            return

        LOGGER.info("Handle DHCP packet")
        dhcp_packet = udp_packet.payload
        LOGGER.debug("dhcp_packet=%s", dhcp_packet)
        # A packet received from client. Find out the switch
        # connected to dhcp server and forward the packet
        if udp_packet.srcport == packet.dhcp.CLIENT_PORT:
            LOGGER.info("Forward DHCP message to DHCP server=%s", DHCP_SERVER)
            if not self.server_switch or not self.server_port:
                LOGGER.warning("DHCP server has not been found!")
                return
            core.openflow.sendToDPID(self.server_switch, of.ofp_packet_out(
                    data=eth_packet.pack(),
                    action=of.ofp_action_output(port=self.server_port)))
        # A packet received from server. Find out the mac address
        # of the client and forward the packet to it.
        elif udp_packet.srcport == packet.dhcp.SERVER_PORT:
            LOGGER.info("Forward DHCP message to client=%s",
                        dhcp_packet.chaddr)
            dpid, port = self.inception.mac_to_dpid_port[dhcp_packet.chaddr]
            core.openflow.sendToDPID(dpid, of.ofp_packet_out(
                    data=eth_packet.pack(),
                    action=of.ofp_action_output(port=port)))
