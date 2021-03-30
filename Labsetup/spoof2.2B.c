#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

#include "headers.h"



#define SRC_IP     "10.0.2.15"
#define DEST_IP    "1.1.1.1"
#define SRC_PORT   42433
#define DEST_PORT  9090 
#define SEQ_NUM    3092566627
#define TCP_DATA   "Hello Server!"

/*********************
  Given an IP packet, send it out using a raw socket.
**********************/
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




unsigned short in_cksum (unsigned short *buf, int length);
/**********************
  Spoof an ICMP echo request using an arbitrary source IP Address
***********************/
int icmpF() {
   char buffer[1024];

   memset(buffer, 0, 1024);

   /*******************
      Step 1: Fill in the ICMP header.
    ********************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

   /*******************
      Step 2: Fill in the IP header.
    ********************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
   ip->iph_destip.s_addr = inet_addr(DEST_IP);
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader));

   /*******************
      Step 3: Finally, send the spoofed packet
    ********************/
   send_raw_ip_packet (ip);

   return 0;
}



int main(){

  icmpF();
  
  return 0;
}













