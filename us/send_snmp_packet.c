/*  constructing dgram and ip header from http://phrack.org/issues/61/13.html */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include "allocate_tun_device.h"
#include "snmp_lib.h"
#include "ip_header_checksum.h"

#define SRC_IP "10.0.0.2"
#define DEST_IP "10.0.0.2"
static unsigned short checksum(int numwords, unsigned short *buff);

int main(int argc, char *argv[])
{
    unsigned char dgram[256];      
    struct iphdr *ip_header = (struct iphdr *)dgram; // iphdr not ip struct is used in sk_buff
    struct udphdr *udphead = (struct udphdr *)(dgram + sizeof(struct iphdr));
    
    struct in_addr my_addr;
    struct in_addr serv_addr;
    u_char snmp_pdu[44];
    size_t message_len;
    
    
    oid get_pid_oid[9] = {1,3,6,1,3,400,1,1,1}; // KERNEL_SERVICES_MIB_GETPID

    encode_get_request(snmp_pdu, &message_len, get_pid_oid, 9);
    printf("message_len %d \n", message_len);
    
    serv_addr.s_addr = inet_addr("10.0.0.2");
    my_addr.s_addr = inet_addr("10.0.0.2");
    
    memset(dgram, 0x00, 256);   
   
    // struct iphdr
    ip_header->ihl = (sizeof(struct iphdr))/4;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(message_len + 28); // 28 = size of ip header(20) + udp header(8)
    ip_header->id = htons(rand());  // converts short int from host to network byte order
    ip_header->frag_off |= ntohs(IP_DF); // converts short int from network to host byte order
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = (u_int32_t)inet_addr(SRC_IP);
    ip_header->daddr = (u_int32_t)inet_addr(DEST_IP);
    ip_header->check = ip_fast_csum((unsigned short *)ip_header, ip_header->ihl);
    

    // fill udp fields, very important here to use htons!
    udphead->source = htons(35190); // randomly chosen source port
    udphead->dest = htons(161); // SNMP port
    udphead->len = htons(message_len+8);  // 8 is size of udp header
    udphead->check = checksum(sizeof(struct udphdr), (unsigned short *)udphead);

    // copy the contructed pdu into datagram buffer
    memcpy((dgram + sizeof(struct iphdr) + sizeof(struct udphdr)), snmp_pdu, message_len);
    // printf("sent message length: %d \n", message_len);
    /* open the tun device
     * before opening the device, make sure it is allocated and configured by running:
     * 1- sudo openvpn --mktun --dev tun2
     * 2- sudo ip link set tun2 up
     * 3- sudo ip addr add 10.0.0.2/24 dev tun2
    */
    char dev_name[IFNAMSIZ];
    int tun_fd, nwrite;
    strcpy(dev_name, "tun2");
    tun_fd = tun_alloc(dev_name);

   
    printf("Sending request...\n");

    nwrite = write(tun_fd, dgram, message_len + 28);
   
    if(nwrite < 0) {
        perror("writing to interface");
        close(tun_fd);        
        exit(1);
    }    

    close(tun_fd);
    
    return 0;
}

// calculates the checksum for the udp header, source: http://phrack.org/issues/61/13.html
static unsigned short checksum(int numwords, unsigned short *buff) {
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   /* add next word, then increment pointer */
   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   
   return ~sum;
}


