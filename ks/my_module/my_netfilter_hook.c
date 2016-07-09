#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/snmp_kernel_callback.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <net/udp.h>
#include <linux/ip.h>
#include "kernel_services_mib.h"
#include "snmplib-kernel.h"

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;

/* Name of the interface we want to drop packets from */
static char *tun_if = "tun2";

/* This is the hook function itself */
unsigned int snmp_hook_func(unsigned int hooknum,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *)) {
  if (strcmp(in->name, tun_if) == 0) {
    struct udphdr *udp_header;
    struct iphdr *ip_header;
    // size_t msg_len;
    
    
    struct snmp_field *recv_message;
    struct snmp_field *recv_community;
    struct snmp_field *recv_request;
    struct snmp_field *error;
    struct snmp_field *recv_varbind_list;
    struct snmp_field *recv_varbind;
    struct snmp_field *recv_object_id;
    struct snmp_field *recv_object_value;

    struct snmp_field *param1_vb;
    struct snmp_field *param2_vb;
    size_t offset = 0;
    
    struct snmp_field syscall_ret_value;
    
    size_t oid_len = 0;
    size_t dec_oid_len = 0;
    u_char command;
    u_int32_t retval = 0;
    u_char e_val;
    long o_ret;
    long c_ret;
    long r_ret;
    char read_buff[50];
    long w_ret;
    size_t service_vb_len = 0, params_len = 0;

    u_char param1_val[50];
    u_char param2_val[10];
    
    size_t p1_val_len, p2_val_len;
    u_int32_t n_int_val;
    int param_int;
    
    if(!skb) return NF_ACCEPT;
    //ip_header = ip_hdr(skb);
    
    ip_header = (struct iphdr*)(skb->data);
    
    if(!ip_header) return NF_ACCEPT; 
      
    if(ip_header->protocol != IPPROTO_UDP) return NF_ACCEPT; // IPPROTO_UDP = 17
    
    udp_header = (struct udphdr*) (skb->data + sizeof(struct iphdr) );
    
    if (!udp_header) return NF_ACCEPT;
    
    // msg_len = ntohs(udp_header->len) - 8; // snmp message length = udp length - udp header which is 8 bytes
    
    if (udp_header->dest != htons(161)) return NF_ACCEPT;
      
    recv_message = (struct snmp_field*)(skb->data + sizeof(struct iphdr) + sizeof(struct udphdr));

    offset = 3; //version field
    recv_community = (struct snmp_field*) (recv_message->value+offset);
    offset += recv_community->length+2;
    
    recv_request = (struct snmp_field*) (recv_message->value+offset);
    command = recv_request->type ;
    offset += 2;
    
    offset += 4; // request id is a 16 bit integer of 2 bytes
  
    error = (struct snmp_field*) (recv_message->value+offset);
  
    offset += error->length + 2 + 3; // offset 3 for error index
    recv_varbind_list = (struct snmp_field*) (recv_message->value+offset);
    offset += 2;
    
    recv_varbind = (struct snmp_field*) (recv_message->value+offset);
    service_vb_len = recv_varbind->length + 2;
    offset += 2;

    recv_object_id = (struct snmp_field*) (recv_message->value+offset);
    offset +=  recv_object_id->length + 2;
    
    oid_len = recv_object_id->length;
    
    unsigned char en_oid[oid_len];      

    memcpy(en_oid,recv_object_id->value, oid_len);

    oid dec_oid[oid_len];

    decode_oid(en_oid, oid_len, dec_oid, &dec_oid_len);
    
    recv_request->type = SNMP_MSG_RESPONSE;
    recv_object_value = (struct snmp_field*) (recv_message->value+offset);

    
    switch (command) {
      case 160: // get request
      
      if (dec_oid[5] == CSUF_PEN && dec_oid[6] == KERNEL_SERVICES_MIB) {
        switch (dec_oid[7]) {
            case SYS_SUBSYSTEM:
            {
                switch (dec_oid[8]) {
                case KERNEL_SERVICES_MIB_PAUSE:
                {
                    retval = htonl(snmp_pause_callback());
                    break;
                }
                break;
                }
            }
        	case SCHED_SUBSYSTEM:
        	  switch (dec_oid[8]) {
        	    case KERNEL_SERVICES_MIB_GETPID:
        	    {
        	      retval = htonl(snmp_getpid_callback());
        	      break;
        	      // printk("snmp kernel: getpid retval : %ld \n", ntohl(retval));
        	    }
                case KERNEL_SERVICES_MIB_GETPPID:
                {
                retval = htonl(snmp_getppid_callback());
                break;
                // printk("snmp kernel: getpid retval : %ld \n", ntohl(retval));
                }
                case KERNEL_SERVICES_MIB_GETGID:
                {
                retval = htonl(snmp_getgid_callback());
                break;
                }
                case KERNEL_SERVICES_MIB_SETSID:
                {
                retval = htonl(snmp_setsid_callback());
                break;
                }
                case KERNEL_SERVICES_MIB_GETUID:
                {
                retval = htonl(snmp_getuid_callback());
                break;
                // printk("snmp kernel: getpid retval : %ld \n", ntohl(retval));
                }
                case KERNEL_SERVICES_MIB_GETEUID:
                {
                retval = htonl(snmp_geteuid_callback());
                break;
                // printk("snmp kernel: getpid retval : %ld \n", ntohl(retval));
                }
                case KERNEL_SERVICES_MIB_NICE:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                o_ret = snmp_nice_callback(param_int);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                } 
        	    case KERNEL_SERVICES_MIB_GETSID:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                pid_t pid = (pid_t) param_int;
                o_ret = snmp_getsid_callback(pid);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                } 
                case KERNEL_SERVICES_MIB_GETPGID:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                pid_t pid = (pid_t) param_int;
                o_ret = snmp_getpgid_callback(pid);
                
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }   
        	  }
        	  break;
            case TIME_SUBSYSTEM:{
              switch (dec_oid[8]) {
                case KERNEL_SERVICES_MIB_TIME:
                  
                  retval = htonl(snmp_time_callback());
                  break;                              
              }
              break;
            } 
            case SIGNAL_SUBSYSTEM:{
              switch (dec_oid[8]) {
                case KERNEL_SERVICES_MIB_KILL:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                pid_t pid = (pid_t) param_int;
                o_ret = snmp_kill_callback(pid,10);
                // o_ret = pid;
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
                            
              }
              break;
            } 
        	case PM_SUBSYSTEM:{
                switch (dec_oid[8]) {
                  case KERNEL_SERVICES_MIB_FORK:
                  {
                    retval = htonl(snmp_fork_callback());
                    break;
                  }
                  case KERNEL_SERVICES_MIB_VFORK:
                  {
                    retval = htonl(snmp_vfork_callback());
                    break;
                  }
                 
                break;
                }
                break;
            }

        	case FS_SUBSYSTEM:
            switch (dec_oid[8]) {
              case KERNEL_SERVICES_MIB_OPEN:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
        		    o_ret = snmp_open_callback(param1_val, param_int);
                
        	     	retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
		            
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_CREAT:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                mode_t mode = (mode_t) param_int;
                o_ret = snmp_creat_callback(param1_val, mode);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_ACCESS:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                mode_t mode = (mode_t) param_int;
                o_ret = snmp_access_callback(param1_val, mode);
                // o_ret = param_int;
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_CHMOD:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                mode_t mode = (mode_t) param_int;
                o_ret = snmp_chmod_callback(param1_val, mode);
                
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_UNLINK:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                
                o_ret = snmp_unlink_callback(param1_val);
                
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_MKDIR:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                mode_t mode = (mode_t) param_int;
                o_ret = snmp_mkdir_callback(param1_val, mode);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
             
              case KERNEL_SERVICES_MIB_RMDIR:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                o_ret = snmp_rmdir_callback(param1_val);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
              case KERNEL_SERVICES_MIB_CHDIR:
                {
                param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);
                
                // note: can decode the oid here to check which params are sent
                p1_val_len = decode_varbind(param1_vb, param1_val);
                param1_val[p1_val_len] = '\0';
                //printk("param1_val %s \n", param1_val);
                
                p2_val_len = decode_varbind(param2_vb, param2_val);
                memcpy(&n_int_val, param2_val, p2_val_len);
                param_int = ntohl(n_int_val);
                //printk("param_int: %d \n", param_int);

                // need to decode the parameters, when sending the response, we need to remove the paramters so the lengths need to be updated differently
                // maybe subtract the length from here and memset varbind_list->value
                // check first if sys_open can be called properly from here
                o_ret = snmp_chdir_callback(param1_val);
                retval = htonl(o_ret);
                params_len = recv_varbind_list->length - service_vb_len;

                memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                recv_varbind_list->length -= params_len;
                recv_request->length -= params_len;
                recv_message->length -= params_len;         
                
                ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                udp_header->len = htons(ntohs(udp_header->len) - params_len);
                skb->len -= params_len;
                break;
                }
                // int
              // case KERNEL_SERVICES_MIB_CLOSE:
                // {
                // param1_vb = (struct snmp_field*) (recv_varbind_list->value + service_vb_len);
                // oid_len = recv_object_id->length;

                // unsigned char en_oid[oid_len];
                // memcpy(en_oid, recv_object_id->value,oid_len);
                // oid dec_oid[oid_len];
                // decode_oid(en_oid, oid_len, dec_oid, &dec_oid_len);

                // u_char param1_val[50];
                // size_t p1_val_len;
                // u_int32_t n_int_val;
          
                // p1_val_len = decode_varbind(param1_vb,param1_val);
                // memcpy(&n_int_val,param1_val, p1_val_len);
                // long param_long1;
                // param_long1 = ntohl(n_int_val);
                // //printk("param_int: %d \n", param_int);
                // //need change to snmp_close_callback
                // //c_ret = snmp_close_callback(param_long1);
                // // c_ret = param_int;
                // // c_ret = close(param_int);
                // retval = htonl(c_ret);
                // params_len = recv_varbind_list->length - service_vb_len;

                // memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                // recv_varbind_list->length -= params_len;
                // recv_request->length -= params_len;
                // recv_message->length -= params_len;         
                
                // ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                // udp_header->len = htons(ntohs(udp_header->len) - params_len);
                // skb->len -= params_len;
                // break;
                // }
                // int int
              // case KERNEL_SERVICES_MIB_READ:
              //   {
                // param1_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len);
                // param2_vb = (struct snmp_field *) (recv_varbind_list->value + service_vb_len + param1_vb->length +2);

                // oid_len = recv_object_id->length;

                // //unsigned char en_oid[oid_len];

                // memcpy(en_oid, recv_object_id->value,oid_len);

                // //oid dec_oid[oid_len];

                // decode_oid(en_oid, oid_len, dec_oid, &dec_oid_len);

                // int param_int1;
                // int param_int2;
         
                // p1_val_len = decode_varbind(param1_vb,param1_val);
                // memcpy(&n_int_val,param1_val, p1_val_len);
                // param_int1 = ntohl(n_int_val);

                // p2_val_len = decode_varbind(param2_vb,param2_val);
                // memcpy(&n_int_val,param2_val, p2_val_len);
                // param_int2 = ntohl(n_int_val);

                // size_t param_sizet2 = (size_t) param_int2;

                // // r_ret = snmp_read_callback(param_int1, read_buff, param_sizet2);
                // r_ret = param_int2;//htonl(r_ret);
                // retval = htonl(r_ret);
                // params_len = recv_varbind_list->length - service_vb_len;

                // memset((recv_varbind_list->value + service_vb_len), 0, params_len);
                    
                // recv_varbind_list->length -= params_len;
                // recv_request->length -= params_len;
                // recv_message->length -= params_len;         
                
                // ip_header->tot_len = htons(ntohs(ip_header->tot_len) - params_len);
                // udp_header->len = htons(ntohs(udp_header->len) - params_len);
                // skb->len -= params_len;
                // break;
                // }
            }
        	  break;

        }
        // contruct the response using the retval from callback functions
        
                  
        syscall_ret_value.type = ASN_INTEGER;    
        syscall_ret_value.length = sizeof(u_int32_t);
        
        // try to use here sizeof(retval)
        memcpy(syscall_ret_value.value, (u_char*)&retval, sizeof(u_int32_t));

        memcpy(recv_object_value, &syscall_ret_value, syscall_ret_value.length+2);             
        
        recv_varbind->length += sizeof(u_int32_t);
        recv_varbind_list->length += sizeof(u_int32_t);
        recv_request->length += sizeof(u_int32_t);
        recv_message->length += sizeof(u_int32_t);          
        
        ip_header->tot_len = htons(ntohs(ip_header->tot_len) + sizeof(u_int32_t));
        udp_header->len = htons(ntohs(udp_header->len) + sizeof(u_int32_t));
        skb->len += sizeof(u_int32_t);  
      
      } else {
        printk("snmp kernel: unrecognized oid \n");
        // return a response message with error set
        recv_request->type = SNMP_MSG_RESPONSE;
        e_val = 2; // no such name
        memcpy(error->value, &e_val, 1);        
      }
      
      break;
      /* only handling get requests for now
        
      case 161: // getnext request
      case 162: // snmp_msg_response
      case 163: // set request 
       */
      }    
    

    // write the response into skb
    memcpy(skb->data, ip_header, sizeof(struct iphdr));
    memcpy((skb->data+sizeof(struct iphdr)), udp_header, sizeof(struct udphdr));     
         
    memcpy((skb->data + sizeof(struct iphdr) + sizeof(struct udphdr)), recv_message, recv_message->length+2);     
    
    dev_queue_xmit(skb);
    
    return NF_STOLEN; 
     
    
  } else {
    return NF_ACCEPT;
  } 
  
}
static int __init my_hook_init(void) {
  printk("initializing my module \n");
  /* Fill in our hook structure */
  nfho.hook     = snmp_hook_func;         // Handler function
  nfho.hooknum  = 0;                      // First hook for IPv4
  nfho.pf       = PF_INET;                // protocol family
  nfho.priority = NF_IP_PRI_FIRST;        //Make our function first

  nf_register_hook(&nfho);
  return 0;
}

static void __exit my_hook_exit(void) {
  printk("cleaning up my module \n");
  nf_unregister_hook(&nfho);
}

module_init(my_hook_init);
module_exit(my_hook_exit);



