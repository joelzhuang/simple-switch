# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct
import threading #used to count traffic
import time #used to sleep
from netaddr import IPAddress
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.controller import handler
from ryu.topology import event, switches

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.startedThread = 0
	
   
    #method for getting the status of the switch. How many packets it has received and sent
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
    	msg = ev.msg
    	ofp = msg.datapath.ofproto
    	body = ev.msg.body

    	for stat in body:
		 
		self.logger.info('Host: %d',stat.port_no)
		self.logger.info( 'received packets: %d sent packets: %d',stat.rx_packets,stat.tx_packets)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))
	
	#need to set priority to 0 so that it does not overwrite other block rules
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def add_flow_ip(self, datapath,src, dst, actions):
        ofproto = datapath.ofproto
	
	#converting ip string to int for match rule
	ipsrc = int(IPAddress(src))
	ipdst = int(IPAddress(dst))

	#making a match by stating the match fields so it can be added to the flow
	#match is added so that next packet is checked against the match fields specified here
	#dl_type = datalink type (ethertype)
        match = datapath.ofproto_parser.OFPMatch(nw_src=ipsrc,nw_dst=ipdst,dl_type=0x0800)
	
	#set priority to 5 so that the priority for block rules is higher than the other rules
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=5,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
	
	#adding match for other direction
        match = datapath.ofproto_parser.OFPMatch(nw_src=ipdst,nw_dst=ipsrc,dl_type=0x0800)
	

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=5,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
	
	#checks if packet is of ethertype ipv4
	if(pkt.get_protocol(ipv4.ipv4)):
		ip = pkt.get_protocol(ipv4.ipv4)
		
		#getting ip destination and source of ipv4 packet
		idst = ip.dst
		isrc = ip.src
		
		#checks if the src and dst is both from h2 and host 3, then adds rule to block
		if((idst=="10.0.0.2" and isrc == "10.0.0.3") or (idst=="10.0.0.3" and isrc == "10.0.0.2")):
			#set actions to empty list so it drops the packet
			actions = {}
		
			#adds flow to switch to block both directions
			self.add_flow_ip(datapath, isrc, idst, actions)
			return
			
	dpid = datapath.id
	self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
          

	 # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
	#install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    #send a request for port status
    def send_port_stats_request(self, datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

	#want the port to be 1 as it is host 1
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, 1)
        datapath.send_msg(req)

    #keep running non-stop in order to receive port status
    def portStatus(self,ev):
	msg = ev.msg
	while(1):
		
	    self.logger.info("port status: \n")
	    #request for port status
	    self.send_port_stats_request(msg.datapath)
	    #wait for one second before requesting again
	    time.sleep(1)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
	
	#code from http://stackoverflow.com/questions/2846653/how-to-use-threading-in-python
	#starting thread for counting traffic for host 1
	if not self.startedThread:
	    t = threading.Thread(target=self.portStatus, args=(ev,))
    	    t.daemon = True
    	    t.start()
	    self.startedThred = 1

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


 
