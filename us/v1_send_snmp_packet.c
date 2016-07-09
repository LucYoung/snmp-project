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
#include "encode_snmp.h"
#include "decode_oid.h"
#include "ip_header_checksum.h"
#include <linux/kernel.h>
#include <sys/syscall.h>
/* Function prototypes */
static unsigned short checksum(int numwords, unsigned short *buff);

int main(int argc, char *argv[])
{
    unsigned char dgram[72];	       /* Plenty for a PING datagram */
    
    // struct ip *iphead = (struct ip *)dgram;
    struct iphdr *ip_header = (struct iphdr *)dgram;
    struct udphdr *udphead = (struct udphdr *)(dgram + sizeof(struct iphdr));
    // struct snmphdr *snmphead = (struct snmphdr *)(dgram + sizeof(struct ip) + sizeof(struct udphdr));
    struct in_addr my_addr;
    struct in_addr serv_addr;  

    // u_char snmp_pdu[44] = {0x30, 0x29}; // type sequence and length is 0x29
    
    // get-request ".1.3.6.1.3.400.1.1.1"
    u_char snmp_pdu[44] = {0x30, 0x2a, /*version*/ 0x02, 0x01, 0x00, /*community*/ 0x04,0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,/* begin pdu*/  0xa0, 0x1d, 0x02, 0x04, 0x28, 0x20, 0x94, 0x7c, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x03, 0x83, 0x10, 0x01, 0x01, 0x01, 0x05, 0x00};
    // u_char snmp_message[44];
    // size_t snmp_message_len;
    u_char snmp_pdu_2[44];
    size_t total_len = 0, header_len = 0, request_len = 0; // total length is length of the header + length of request
    struct snmp_field snmp_message;
    snmp_message.type = ASN_OPAQUE_TAG2; 
    snmp_message.length = 42;
    memset(snmp_message.value, 0x00, snmp_message.length);
    // will fill the length and value later

    printf("version\n"); 
    struct snmp_field version;
    version.type = ASN_INTEGER;
    version.length = 1;    
    
    u_char v_value = SNMP_VERSION_1;
    strncpy(version.value, &v_value, 1);

    header_len += version.length+2;
    memcpy(snmp_message.value, &version, sizeof(version));   
    
    printf("community\n"); 
    struct snmp_field community;
    community.type = ASN_OCTET_STR;
    community.length = (u_char)strlen("public");
    strncpy(community.value, "public", strlen("public")+1);
    
    memcpy((snmp_message.value +header_len), &community, community.length+2);
    header_len += community.length+2;  

    printf("request\n");
    struct snmp_field request;
    request.type = SNMP_MSG_GET;
    request.length = 29;
    // request.value will be filled later with the request
     // next there is request id, error,error index, varbind list    

    printf("request_id\n");
    struct snmp_field request_id;
    request_id.type = ASN_INTEGER;
    request_id.length = sizeof(int);
    int req_val = rand();
    strncpy(request_id.value, (u_char*)&req_val, sizeof(int));
    
    memcpy(request.value, &request_id,request_id.length+2);
    request_len += request_id.length+ 2;

    printf("error\n");
    struct snmp_field error;
    error.type = ASN_INTEGER;
    error.length = 1;
    u_char e_val = 0;
    strncpy(error.value, &e_val, 1);

    memcpy(request.value+request_len, &error,error.length+2);
    request_len += error.length+ 2;

    printf("error index\n");
    struct snmp_field error_index;
    error_index.type = ASN_INTEGER;
    error_index.length = 1;    
    strncpy(error_index.value, &e_val, 1);

    memcpy(request.value+request_len, &error_index,error_index.length+2);
    request_len += error_index.length+ 2;

    struct snmp_field varbind_list;
    varbind_list.type = ASN_OPAQUE_TAG2; // sequence
    varbind_list.length = 0x0f; // needs to be updated later
    // varbind_list.value = is the linked list of varbinds, copy a_varbind into it

    struct snmp_field a_varbind; 
    a_varbind.type = ASN_OPAQUE_TAG2; // sequence
    a_varbind.length = 0x0d; // needs to be updated later
    // a_varbind.value = copy get_pid_object and value into it
    
    // struct varbind get_pid;
    struct snmp_field get_pid_object;
    struct snmp_field get_pid_value;

    get_pid_object.type = ASN_OBJECT_ID;
    get_pid_object.length = 9;

    // oid get_pid_oid[MAX_OID_LEN] = {1,3,6,1,3,400,1,1,1}

    // need to encode it based on BER for the oid
    u_char get_pid_oid[9] = {0x2b, 0x06, 0x01, 0x03, 0x83, 0x10, 0x01, 0x01, 0x01};
    strncpy(get_pid_object.value, get_pid_oid, get_pid_object.length);
    
    // get_pid.object_id = get_pid_object;
    memcpy(a_varbind.value, &get_pid_object, get_pid_object.length+2);

    get_pid_value.type = ASN_NULL;
    get_pid_value.length = 0;

    memcpy(a_varbind.value+get_pid_object.length+2, &get_pid_value, 2);
    memcpy(varbind_list.value, &a_varbind, a_varbind.length+2);
    memcpy(request.value+request_len, &varbind_list,varbind_list.length+2);

    request_len += varbind_list.length+2;    
    
    memcpy((snmp_message.value + header_len), &request, request_len+2);
    memcpy(snmp_pdu_2, &snmp_message, snmp_message.length+2);
    
    
    serv_addr.s_addr = inet_addr("10.0.0.2");
    my_addr.s_addr = inet_addr("10.0.0.2");
    
    memset(dgram, 0x00, 72);   
   

    // struct iphdr
    ip_header->ihl = (sizeof(struct iphdr))/4;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(72);
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
    udphead->len = htons(52);
    udphead->check = checksum(42, (unsigned short *)udphead);

    // copy the contructed pdu into datagram buffer
    memcpy((dgram + sizeof(struct iphdr) + sizeof(struct udphdr)), snmp_pdu_2, sizeof(snmp_pdu_2));

    
    char dev_name[IFNAMSIZ];
    int tun_fd, nwrite;
    strcpy(dev_name, "tun2");
    tun_fd = tun_alloc(dev_name);

    /* Finally, send the packet */
    fprintf(stdout, "Sending request...\n");

    nwrite = write(tun_fd, dgram, sizeof(dgram));
   
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


