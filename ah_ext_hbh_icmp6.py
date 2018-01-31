#!/usr/local/bin/python2.7
# send ping6 AH packet with hop-by-hop extension header

import os
import threading
from addr import *
from scapy.all import *

class Sniff1(threading.Thread):
	filter = None
	captured = None
	packet = None
	def run(self):
		self.captured = sniff(iface=SRC_OUT_IF, filter=self.filter,
		    count=1, timeout=3)
		if self.captured:
			self.packet = self.captured[0]

dstaddr=sys.argv[1]
pid=os.getpid()
eid=pid & 0xffff
payload="ABCDEFGHIJKLOMNO"
packet=IPv6(src=SRC_OUT_IPV6, dst=dstaddr)/IPv6ExtHdrHopByHop()/AH(spi=0x10002462,nh=socket.IPPROTO_ICMPV6)/ICMPv6EchoRequest(id=eid, data=payload)
packet.show2()
eth=[]
eth.append(Ether(src=SRC_OUT_MAC, dst=IPS_IN_MAC)/packet)

sniffer = Sniff1();
sniffer.filter = "ip6 and src %s and dst %s and icmp6" % (dstaddr, SRC_OUT_IPV6)
sniffer.start()
time.sleep(1)
sendp(eth, iface=SRC_OUT_IF)
sniffer.join(timeout=5)
a = sniffer.packet

