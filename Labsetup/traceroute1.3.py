#!/usr/bin/env python3
from scapy.all import*

##in the loop I deacrese ttl i++
##build the objects ip,icmp 
##send packet.if no ip skip else print the ip back
##if I in the last iteration -finsh and print the 
##iteration

for i in range(1,22):
    a = IP()
    a.dst = '1.1.1.1'
    a.ttl = i
    b = ICMP()
    answer=sr1(a/b)
    if answer is None:
       print("no ip")
    
    else:
       print("IP of the back: ",answer.src)
       if i==21:
          print("last iteration :",i)
