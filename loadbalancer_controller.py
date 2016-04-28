'''
Help and code snippets taken from Ryu/app/simple_switch.py and simple_switch_ 13.py

'''
import logging
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet
import ryu.app.ofctl.api
import ryu.app.ofctl_rest

LOG = logging.getLogger('ARP Debug Logging')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION] #Openflow version 1.0

    # __init__ function taken form ryu examples
    def __init__(self, *args, **kwargs):
        super( LoadBalancer, self).__init__(*args, **kwargs)
        self.portTonext = 2 #Will be used for round robin
        self.LB1_portTonext = 1
        self.LB2_portTonext = 2
        self.mac_to_port = {} # used for strong mac to port bindings for self learning capabilities
        # These are the IP and macs that need to be changed by the flow tables
        self.loadBalancer_1 = []
        self.loadBalancer_2 = []
        self.loadBalancer_1.append((1,'10.0.0.100','00:01:00:00:00:00'))
        self.loadBalancer_1.append((2,'10.0.0.5','00:00:00:00:05:00'))
        self.loadBalancer_1.append((3,'10.0.0.6','00:00:00:00:06:00'))

        self.loadBalancer_2.append((1,'10.0.0.200','00:02:00:00:00:00'))
        self.loadBalancer_2.append((2,'10.0.0.7','00:00:00:00:07:00'))
        self.loadBalancer_2.append((3,'10.0.0.8','00:00:00:00:08:00'))

        self.firewall = {}
        self.firewall[1] = False
        self.firewall[2] = False
        self.firewall_rules = {}
        self.firewall_rules[1] = ('10.0.0.1', 80, '10.0.0.2', 443)
        self.firewall_rules[2] = ('10.0.0.3', 80, '10.0.0.4', 443)

    def add_specific_rule_for_forward(self, datapath, msg, src_mac_address):
        # uses the protocol inside the switches (in our case 1.0 otherwise will generate warnings)
        ofproto = datapath.ofproto
        portToip_bindings = []
        LB_ID = 0
        '''
        Check LoadBalancer ID
        '''
        if datapath.id == 3:
            portToip_bindings = self.loadBalancer_1
            portTonext = self.LB1_portTonext
            LB_ID = 1
        elif datapath.id == 4:
            portToip_bindings = self.loadBalancer_2
            portTonext = self.LB2_portTonext
            LB_ID = 2
        else:
            self.logger.info("switchID is: %d\n",datapath.id)


        '''
        Flow entries
        '''
        # Matching the input port and src mac from where the packet is coming from so that we can have multiple
        # flows. A unique for a client. Without the src mac matching when another clinet tries to connect to server
        # the flow entry of the previous clinet will be applied to it and packets will be dropped
        match = datapath.ofproto_parser.OFPMatch(
            in_port = msg.in_port, dl_src = src_mac_address)

        out_port = 0
        action = []

        if(msg.in_port == 1):
            tmp = portToip_bindings[portTonext]
            action.append(datapath.ofproto_parser.OFPActionSetDlDst(tmp[2]))
            action.append(datapath.ofproto_parser.OFPActionSetNwDst(tmp[1]))
            action.append(datapath.ofproto_parser.OFPActionOutput(tmp[0]))
            self.logger.info("Flow Towards Server at %d to server %s added\n", LB_ID, tmp[1])
            if LB_ID == 1:
                if self.LB1_portTonext == 1:
                    self.LB1_portTonext = 2
                else:
                    self.LB1_portTonext = 1
            elif LB_ID == 2:
                if self.LB2_portTonext == 1:
                    self.LB2_portTonext = 2
                else:
                    self.LB2_portTonext = 1
        else:
            tmp = portToip_bindings[0]
            action.append(datapath.ofproto_parser.OFPActionSetDlSrc(tmp[2]))
            action.append(datapath.ofproto_parser.OFPActionSetNwSrc(tmp[1]))
            action.append(datapath.ofproto_parser.OFPActionOutput(tmp[0]))
            self.logger.info("Flow Towards client at %d to server %s added\n", LB_ID, tmp[1])

        '''
        Add flow table for future packets (only for the current in_port host)
        '''
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=80, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=action)

        # self.logger.info(mod)
        datapath.send_msg(mod) #add the flow entry

    def add_flow(self, datapath, in_port, dst, src, actions): #This add flow function used for adding flows for self learning switch
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src)) #match src/dst mac and in_port

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    def firewall_flows(self, datapath, in_port):
        self.firewall[datapath.id] = True
        ofproto = datapath.ofproto
        match_tcp_port = datapath.ofproto_parser.OFPMatch(dl_type= ether.ETH_TYPE_IP,
        nw_proto= inet.IPPROTO_TCP,
        nw_src= self.firewall_rules[datapath.id][0],
        tp_dst= self.firewall_rules[datapath.id][1]) #match src mac and tcp port

        actions = []
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match_tcp_port, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)

        match_tcp_port = datapath.ofproto_parser.OFPMatch(dl_type= ether.ETH_TYPE_IP,
        nw_proto= inet.IPPROTO_TCP,
        nw_src= self.firewall_rules[datapath.id][2],
        tp_dst= self.firewall_rules[datapath.id][3]) #match src mac and tcp port
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match_tcp_port, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    # set the Packet in event listener in the MAIN_DISPATCHER phase. In this phase we can make changes to the switch config else we
    # will not be able to make changes to the switch config.
    # We will look at the RoundRobin State and based on that balance the incoming TCP connection.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def inputHandler(self, ev):
        msg = ev.msg #openflow message recieved by the controller form the switch
        datapath = msg.datapath #extract the switchId from the message
        if datapath.id == 1 or datapath.id == 2:
            if not self.firewall[datapath.id]:
                self.firewall_flows(datapath, msg.in_port) # add firewall

        ofproto = datapath.ofproto #Extract openflow protocol number (in our case 1.0)

        pkt = packet.Packet(msg.data) # extract the packet data from the message recieved from the switch
                                     # This is used when sending packet to the switch again or if we need to do DPI (deep packet inspection)

        eth_header = pkt.get_protocol(ethernet.ethernet) #get ethernet headers for the packet
        ipv4_header = pkt.get_protocol(ipv4.ipv4) #get ipv4 headers for the packet to look at ip address
                                                  #for debugging purpose

        # Get src and dst mac addresses
        dst_mac_address = eth_header.dst
        src_mac_address = eth_header.src

        #switchID is the datapth Id
        switchID = datapath.id

        if ipv4_header != None:
            self.logger.info("packet in switch: %s with mac src: %s and dest mac:%s with in_port: %s and ipv4 src and dst address as: %s -- %s", switchID, src_mac_address, dst_mac_address, msg.in_port, ipv4_header.src, ipv4_header.dst)
        else:
            self.logger.info("packet in switch: %s with mac src: %s and dest mac:%s with in_port: %s", switchID, src_mac_address, dst_mac_address, msg.in_port)

        self.mac_to_port.setdefault(switchID, {})
        self.mac_to_port[switchID][src_mac_address] = msg.in_port #store the currnet mac of the sender so that the reply packet does not flood

        '''
        Look if ARP for LoadBalancers
        '''
        #LoadBalancer 1
        etherFrame = pkt.get_protocol(ethernet.ethernet)
        if switchID == 3: #3 is the switchid for LoadBalancer 1
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                arpPacket = pkt.get_protocol(arp.arp)
                if arpPacket.dst_ip == '10.0.0.100': #if arp for the loadbalancer then send arp reply to requesting client
                    self.receive_arp(datapath, pkt, etherFrame, msg.in_port)
                    LOG.debug("ARP packet Recieved")
                    return 0 #stop after sending the ARP reply
                elif arpPacket.dst_ip == '10.0.0.200':
                    return 0
            elif ipv4_header.proto == inet.IPPROTO_TCP: #if the recieved packet has TCP headers then add flows for tcp forwarding
                self.logger.info('TCP Packet Recieved with src mac as: %s', src_mac_address)
                self.add_specific_rule_for_forward(datapath, msg, src_mac_address)
                return 0 #end after adding flow for handling tcp for that host
            else:
                self.logger.info('Something other than ARP/TCP recieved at LoadBalancer') #this case is for icmp packets

        if switchID == 4: #3 is the switchid for LoadBalancer 1
            if etherFrame.ethertype == ether.ETH_TYPE_ARP:
                arpPacket = pkt.get_protocol(arp.arp)
                if arpPacket.dst_ip == '10.0.0.200': #if arp for the loadbalancer then send arp reply to requesting client
                    self.receive_arp(datapath, pkt, etherFrame, msg.in_port)
                    LOG.debug("ARP packet Recieved")
                    return 0 #stop after sending the ARP reply
                elif arpPacket.dst_ip == '10.0.0.100':
                    return 0
            elif ipv4_header.proto == inet.IPPROTO_TCP: #if the recieved packet has TCP headers then add flows for tcp forwarding
                self.logger.info('TCP Packet Recieved with src mac as: %s', src_mac_address)
                self.add_specific_rule_for_forward(datapath, msg, src_mac_address)
                return 0 #end after adding flow for handling tcp for that host
            else:
                self.logger.info('Something other than ARP/TCP recieved at LoadBalancer') #this case is for icmp packets

        # These conditions check if the dst mac is already learned ot not. then add flows for self learning switch
        if dst_mac_address in self.mac_to_port[switchID]:
            out_port = self.mac_to_port[switchID][dst_mac_address]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst_mac_address, src_mac_address, actions)
            self.logger.info("Flow added at switch: %s ", switchID)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)


    '''
    ARP Request handler taken from ryu/app/simpleArp.py
    '''
    def receive_arp(self, datapath, pkt, etherFrame, inPort):
        arpPacket = pkt.get_protocol(arp.arp)
        if arpPacket.opcode == 1: #opcode 1 means arp request
            arp_dstIp = arpPacket.dst_ip
            LOG.debug("receive ARP request %s => %s (port%d) at Switch: %d"
            %(etherFrame.src, etherFrame.dst, inPort, datapath.id))
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort) # create a ARP reply
        elif arpPacket.opcode == 2:
            LOG.debug('ARP Reply came so packet dropped')

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        if arp_dstIp == '10.0.0.100': #ARP constructed for the LoadBalancer
            srcMac = '00:01:00:00:00:00' #mac of port connected to switch s5 (entry point for the LoadBalancer load)
            outPort = 1
        #this will be used when second load balancer is added
        elif arp_dstIp == '10.0.0.200':
            srcMac = '00:02:00:00:00:00'
            outPort = 1
        else:
            LOG.debug("unknown arp requst received !")
            LOG.debug('dst_ip for ARP request was: %s', arp_dstIp)
            return 1

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort) #send the ARP reply packet back to requesting host
        LOG.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))


    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
        datapath=datapath,
        buffer_id=0xffffffff,
        in_port=datapath.ofproto.OFPP_CONTROLLER,
        actions=actions,
        data=p.data)
        datapath.send_msg(out)
