#!/usr/bin/env python3
from scapy.all import*
##in sniff I do the exactly way until now
##in spoofing I cheak if the icmp packet is requst
##if it is I change only the icmp type to 0
##-reply and chnge the source and destination
def spoofing(pkt):
  if pkt[ICMP].type==8:
    dst=pkt[IP].dst
    src=pkt[IP].src
    ihll=pkt[IP].ihl
    
    idd=pkt[ICMP].id
    seqq=pkt[ICMP].seq
    load=pkt[Raw].load
    
    a=IP(src=dst,dst=src,ihl=ihll)
    b=ICMP(type=0,id=idd,seq=seqq)
    c=load
    ans=(a/b/c)
    send(ans)
    
    
    
  
  
pkt = sniff(iface='enp0s3', filter='icmp', prn=spoofing)
