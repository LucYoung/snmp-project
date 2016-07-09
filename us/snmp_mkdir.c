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

static unsigned short checksum(int numwords, unsigned short *buff);

int snmp_mkdir(u_char *filename, size_t fn_len, mode_t mode) {
    unsigned char dgram[256];	       
    
    struct iphdr *ip_header = (struct iphdr *)dgram; // iphdr not ip struct is used in sk_buff
    struct udphdr *udphead = (struct udphdr *)(dgram + sizeof(struct iphdr));
    
    struct in_addr my_addr;
    struct in_addr serv_addr;
    u_char snmp_pdu[256];  // must be careful with this, using a small value when sending parameters malformed the packet
    size_t message_len;
    
    
    oid mkdir_oid[9] =      {1,3,6,1,3,400,1,3,4};      // KERNEL_SERVICES_MIB_MKDIR
    oid filename_oid[10] = {1,3,6,1,3,400,1,3,4,1};     // KERNEL_SERVICES_MIB_MKDIR_FILE_NAME
    oid mode_oid[10] =    {1,3,6,1,3,400,1,3,4,2};      // KERNEL_SERVICES_MIB_MKDIR_MODE

    int flags = (int) mode;

    encode_get_request_with_params(snmp_pdu, &message_len, mkdir_oid, 9, filename_oid, 10, filename, fn_len, mode_oid, 10, flags);
    
    serv_addr.s_addr = inet_addr("10.0.0.2");
    my_addr.s_addr = inet_addr("10.0.0.2");
    
    memset(dgram, 0x00, 256);   
   
    // struct iphdr
    ip_header->ihl = (sizeof(struct iphdr))/4;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(message_len + 28);
    ip_header->id = htons(rand());
    ip_header->frag_off |= ntohs(IP_DF);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = (u_int32_t)inet_addr("10.0.0.2");
    ip_header->daddr = (u_int32_t)inet_addr("10.0.0.2");
    ip_header->check = ip_fast_csum((unsigned short *)ip_header, ip_header->ihl);
    

    // fill udp fields, very important here to use htons!
    udphead->source = htons(35190);
    udphead->dest = htons(161);
    udphead->len = htons(message_len+8);  // length is very important
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

   
    // printf("Sending request...\n");

    nwrite = write(tun_fd, dgram, message_len + 28);
   
    if(nwrite < 0) {
        perror("writing to interface");
        close(tun_fd);        
        exit(1);
    }

    unsigned char recv_buff[1500];
    int nread, received = 0;    
    
    while(!received) {
        nread = read(tun_fd, recv_buff, 1500);
        if (nread < 0) {
            perror("error reading from device");
            close(tun_fd);
            exit(1);
        } else {
            // printf("read %d bytes \n", nread);
            received = 1;
        }
    }

    // modify the message to send a response, snmp_pdu
    struct snmp_field *response_message;
    pid_t retval;

    response_message = (struct snmp_field*) (recv_buff+sizeof(struct iphdr) + sizeof(struct udphdr));
    decode_get_response(response_message, &retval);

    close(tun_fd);
    if (retval)
        return retval;
    else
        return -1;
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


