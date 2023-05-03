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
from ext import priority

LOGGER = core.getLogger()


class Inception(object):
    """
    Inception cloud SDN controller
    """

    def __init__(self, ip_prefix):
        """
        :param ip_prefix: X1.X2 in network's IP address X1.X2.X3.X4
        """
        self.ip_prefix = ip_prefix
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
            return

        self.dpid_to_ip[switch_id] = ip
        LOGGER.info("Add: switch=%s -> ip=%s", dpid_to_str(switch_id), ip)

        # Collect port information.  Sift out ports connecting peer
        # switches and store them in dpid_ip_to_port
        for port in switch_features.ports:
            # TODO(changbl): Parse the port name to get the IP address
            # of remote rVM to which the bridge builds a VXLAN. E.g.,
            # obr1_184-53 => ip_prefix.184.53. Only store
            # the port connecting remote rVM.
            all_ports.append(port.port_no)
            if port.name.startswith('obr') and '_' in port.name:
                _, ip_suffix = port.name.split('_')
                ip_suffix = ip_suffix.replace('-', '.')
                peer_ip = '.'.join((self.ip_prefix, ip_suffix))
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

        # Intercepts all ARP packets and send them to the controller
        core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_type=0x0806),
            action=of.ofp_action_output(port=of.OFPP_CONTROLLER),
            priority=priority.ARP))

        # Intercepts DHCP packets and send them to the controller
        core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_type=0x0800, nw_proto=17, tp_src=68),
            action=of.ofp_action_output(port=of.OFPP_CONTROLLER),
            priority=priority.DHCP))

        # Set up flow at the currently connected switch
        # On receiving a broadcast message, the switch forwards
        # it to all non-vxlan ports
        # TODO(chenche): need to setup more flows for new hosts in the future
        broadcast_ports = [of.ofp_action_output(port=port_no)
                          for port_no in host_ports]
        core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
            match=of.ofp_match(dl_dst=ETHER_BROADCAST),
            action=broadcast_ports,
            priority=priority.SWITCH_BCAST))

        # Default flows: Process via normal L2/L3 legacy switch configuration
        core.openflow.sendToDPID(switch_id, of.ofp_flow_mod(
            action=of.ofp_action_output(port=of.OFPP_NORMAL),
            priority=priority.NORMAL))

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
            dpid, _ = self.mac_to_dpid_port[mac]
            if dpid == switch_id:
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
        update self.mac_to_dpid_port table. Also set up flow table for
        forwarding broadcast message
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
                priority=priority.HOST_BCAST))
            LOGGER.info("Learn: host=%s -> (switch=%s, port=%s)",
                        eth_packet.src, dpid_to_str(event.dpid), event.port)


def launch(ip_prefix):
    """ Register the component to core
    """
    color.launch()
    log.launch(format="%(asctime)s - %(name)s - %(levelname)s - "
               "%(threadName)s - %(message)s")
    core.registerNew(Inception, ip_prefix)
    LOGGER.info("InceptionArp is started...")
