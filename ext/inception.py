"""
Inception Cloud SDN controller
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ETHER_BROADCAST
from pox import log
from pox.log import color
import pox.openflow.libopenflow_01 as of
from ext.inception_arp import InceptionArp
from ext.inception_dhcp import InceptionDhcp

LOGGER = core.getLogger()

IP_PREFIX = "10.2"

FWD_PRIORITY = 15
HOST_BCAST_PRIORITY = 18
SWITCH_BCAST_PRIORITY = 17


class Inception(object):
    """
    Inception cloud SDN controller
    """

    def __init__(self):
        core.openflow.addListeners(self)
        ## data stuctures
        # dpid -> IP address: records the mapping from switch dpid) to
        # IP address of the rVM where it resides. This table is to
        # facilitate the look-up of dpid_ip_to_port
        self.dpid_to_ip = {}
        # (dpid, IP address) -> port: records the neighboring
        # relationship between switches. It is mapping from data path
        # ID (dpid) of a switch and IP address of neighboring rVM to
        # port number. Its semantics is that each entry stands for
        # connection between switches via some specific port. VXLan,
        # however, only stores information of IP address of rVM in
        # which neighbor switches lies.  Rather than storing the
        # mapping from dpid to dpid directly, we store mapping from
        # dpid to IP address. With further look-up in dpid_to_ip, the
        # dpid to dpid mapping can be retrieved.
        self.dpid_ip_to_port = {}
        # MAC => (dpid, port): mapping from host MAC address to (switch
        # dpid, switch port) of end hosts
        self.mac_to_dpid_port = {}
        # Store port information of each switch
        self.dpid_to_ports = {}
        ## modules
        # ARP
        self.inception_arp = InceptionArp(self)
        # DHCP
        self.inception_dhcp = InceptionDhcp(self)

    def _handle_ConnectionUp(self, event):
        """
        Handle when a switch is connected
        """
        switch_id = event.dpid
        switch_features = event.ofp
        connection = event.connection
        sock = connection.sock
        ip, port = sock.getpeername()
        host_ports = []
        all_ports = []

        # If the entry corresponding to the MAC already exists
        if switch_id in self.dpid_to_ip:
            LOGGER.info("switch=%s already connected", dpid_to_str(switch_id))
        else:
            self.dpid_to_ip[switch_id] = ip
            LOGGER.info("Add: switch=%s -> ip=%s", dpid_to_str(switch_id), ip)

        # Collect port information.  Sift out ports connecting peer
        # switches and store them in dpid_ip_to_port
        for port in switch_features.ports:
            # TODO(changbl): Parse the port name to get the IP
            # address of remote rVM to which the bridge builds a
            # VXLAN. E.g., obr1_184-53 => IP_PREFIX.184.53. Only store
            # the port connecting remote rVM.
            all_ports.append(port.port_no)
            if port.name.startswith('obr') and '_' in port.name:
                _, ip_suffix = port.name.split('_')
                ip_suffix = ip_suffix.replace('-', '.')
                peer_ip = '.'.join((IP_PREFIX, ip_suffix))
                self.dpid_ip_to_port[(switch_id, peer_ip)] = port.port_no
                LOGGER.info("Add: (switch=%s, peer_ip=%s) -> port=%s",
                            dpid_to_str(switch_id), peer_ip, port.port_no)
            elif port.name == 'eth_dhcp':
                self.inception_dhcp.update_server(switch_id, port.port_no)
                LOGGER.info("DHCP server is found!")
            else:
                # Store the port connecting local hosts
                host_ports.append(port.port_no)

        # Store the mapping from switch dpid to ports
        self.dpid_to_ports[event.dpid] = all_ports

        # Set up flow at the currently connected switch
        # On receiving a broadcast message, the switch forwards
        # it to all non-vxlan ports
        broadcast_ports = [of.ofp_action_output(port=port_no)
                          for port_no in host_ports]
        core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_dst=ETHER_BROADCAST),
            action=broadcast_ports,
            priority=BCAST_PRIORITY))

    def _handle_ConnectionDown(self, event):
        """
        Handle when a switch turns off connection
        """
        switch_id = event.dpid
        # Delete switch's mapping from switch dpid to remote IP address
        LOGGER.info("Del: switch=%s -> ip=%s", dpid_to_str(switch_id),
                    self.dpid_to_ip[switch_id])
        del self.dpid_to_ip[switch_id]

        # Delete all its port information
        del self.dpid_to_ports[switch_id]
        for key in self.dpid_ip_to_port.keys():
            (dpid, ip) = key
            if switch_id == dpid:
                LOGGER.info("Del: (switch=%s, peer_ip=%s) -> port=%s",
                            dpid_to_str(dpid), ip, self.dpid_ip_to_port[key])
                del self.dpid_ip_to_port[key]

        # Delete all connected hosts
        for mac in self.mac_to_dpid_port.keys():
            if self.mac_to_dpid_port[mac] == switch_id:
                del self.mac_to_dpid_port[mac]

    def _handle_PacketIn(self, event):
        """
        Handle when a packet is received
        """
        # If packet is not parsed properly, alert and return
        eth_packet = event.parsed
        if not eth_packet.parsed:
            LOGGER.warning("Unparsable packet")
            return

        # do source learning
        self._do_source_learning(event)
        # handle ARP packet if it is
        self.inception_arp.handle(event)
        # handle DHCP packet if it is
        self.inception_dhcp.handle(event)

    def _do_source_learning(self, event):
        """
        Learn MAC => (switch dpid, switch port) mapping from a packet,
        update self.mac_to_dpid_port table
        set up flow table for forwarding broadcast message
        """
        eth_packet = event.parsed
        if eth_packet.src not in self.mac_to_dpid_port:
            self.mac_to_dpid_port[eth_packet.src] = (event.dpid, event.port)
            # Set up broadcast flow when local hosts are sources
            broadcast_ports = [of.ofp_action_output(port=port_no)
                              for port_no in
                              self.dpid_to_ports[event.dpid]
                              if port_no != event.port]
            core.openflow.sendToDPID(event.dpid, of.ofp_flow_mod(
                match=of.ofp_match(dl_src=eth_packet.src,
                                   dl_dst=ETHER_BROADCAST),
                action=broadcast_ports,
                priority=SRC_BCAST_PRIORITY))
            LOGGER.info("Learn: host=%s -> (switch=%s, port=%s)",
                        eth_packet.src, dpid_to_str(event.dpid), event.port)

    def setup_fwd_flows(self, switch_id, dst_mac):
        """
        Given a switch and dst_mac address, setup two flows for data forwarding
        on the switch and its peer switch if the two are not the same. If the
        same, setup only one flow.
        """
        (peer_switch_id, peer_fwd_port) = self.mac_to_dpid_port[dst_mac]
        peer_ip = self.dpid_to_ip[peer_switch_id]
        # two switches are different, setup a first flow at switch
        if switch_id != peer_switch_id:
            fwd_port = self.dpid_ip_to_port[(switch_id, peer_ip)]
            core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
                match=of.ofp_match(dl_dst=dst_mac),
                action=of.ofp_action_output(port=fwd_port),
                priority=FWD_PRIORITY))
            LOGGER.info("Setup forward flow on switch=%s for dst_mac=%s",
                        dpid_to_str(switch_id), dst_mac)
        # Setup flow at the peer switch
        core.openflow.sendToDPID(peer_switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_dst=dst_mac),
            action=of.ofp_action_output(port=peer_fwd_port),
            priority=FWD_PRIORITY))
        LOGGER.info("Setup forward flow on switch=%s for dst_mac=%s",
                    dpid_to_str(peer_switch_id), dst_mac)


def launch():
    """ Register the component to core"""
    color.launch()
    log.launch(format="%(asctime)s - %(name)s - %(levelname)s - "
               "%(threadName)s - %(message)s")
    core.registerNew(Inception)
    LOGGER.info("InceptionArp is started...")
