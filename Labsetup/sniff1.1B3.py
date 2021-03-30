#!/usr/bin/env python3
from scapy.all import*


def print_pkt(pkt):
  pkt.show()
  
  
pkt = sniff(iface='enp0s3', filter=' net 2.20.0.0/16', prn=print_pkt)

##1A-'icmp'
##1BB-'tcp and src host 10.9.0.5 and dst port 23'
##1CC-'src net 128.230.0.0/16'.                     
##filter='icmp',
