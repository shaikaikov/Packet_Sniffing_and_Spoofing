#!/usr/bin/env python3
from scapy.all import*
##buidl objects IP and ICMP spoof source IP 1.2.3.4
## send to the victim(10.0.2.15)
## a/b -payload.
a = IP()
a.src='1.2.3.4'
a.dst = '10.0.2.15'
b = ICMP()
send(a/b)
