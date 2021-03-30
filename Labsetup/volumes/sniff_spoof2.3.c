#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

#include "headers.h"

#define MACNAME "enp0s3"
unsigned short in_cksum (unsigned short *buf, int length);




void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}


void spoof_reply(struct ipheader* ip)
{
    const char buffer[1024];
    int ip_header_len = ip->iph_ihl * 4;
    struct icmpheader* icmp = (struct icmpheader *) ((u_char *)ip + 
                                                  ip_header_len);
    

    // Step 1: Make a copy from the original packet 
    memset((char*)buffer, 0, 1024);
    memcpy((char*)buffer, ip, ntohs(ip->iph_len));
    struct ipheader  * newip  = (struct ipheader *) buffer;
    struct icmpheader * newicmp = (struct icmpheader *) (buffer + ip_header_len);
    
    newicmp->icmp_type=0;
    //newicmp->icmp_chksum=0;
    //newicmp->icmp_chksum=in_cksum((unsigned short *)newicmp,sizeof(struct icmpheader));

    

    
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 50; // Rest the TTL field
    

    //  Send out the spoofed IP packet
    send_raw_ip_packet(newip);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

      

    /* determine protocol */
    if(ip->iph_protocol==IPPROTO_ICMP) { 
       spoof_reply(ip);
       
    }
  }                                
        
}



int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] = 8";
  bpf_u_int32 net;
  //"br-7b67a5084f89"
  // Step 1: Open live pcap session on NIC with name enp0s3
  char* dev=pcap_lookupdev(errbuf);
  handle = pcap_open_live("br-7b67a5084f89", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}    
