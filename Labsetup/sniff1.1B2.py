#!/usr/bin/env python3
from scapy.all import*


def print_pkt(pkt):
  pkt.show()
  
  
pkt = sniff(iface='br-7b67a5084f89', filter='tcp and src host 10.9.0.5 and dst port 23', prn=print_pkt)

##1A-'icmp'
##1BB-'tcp and src host 10.9.0.5 and dst port 23'
##1CC-'src net 128.230.0.0/16'.                     
##filter='icmp',
