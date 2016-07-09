#include <sys/types.h>

typedef u_short oid; // taken from <net-snmp/library/oid.h>
#define MAX_OID_LEN     128 // taken from net-snmp/types.h

// types from net-snmp/library/asn1.h
#define ASN_BOOLEAN     ((u_char)0x01)
#define ASN_INTEGER     ((u_char)0x02)
#define ASN_BIT_STR     ((u_char)0x03)
#define ASN_OCTET_STR ((u_char)0x04)
#define ASN_NULL      ((u_char)0x05)
#define ASN_OBJECT_ID ((u_char)0x06)
#define ASN_SEQUENCE  ((u_char)0x10)
#define ASN_OPAQUE_TAG2 ((u_char)0x30)

// from net-snmp/library/snmp.h
#define SNMP_VERSION_1      0
#define SNMP_VERSION_2c     1
#define SNMP_VERSION_3      3
#define SNMP_MSG_GET    ((u_char)160)
#define SNMP_MSG_GETNEXT  161
#define SNMP_MSG_RESPONSE   162
#define SNMP_MSG_SET    163

//kernel/sched
#define KERNEL_SERVICES_MIB_GETPID	".1.3.6.1.3.400.1.1.1"
#define KERNEL_SERVICES_MIB_GETPPID ".1.3.6.1.3.400.1.1.2" 
#define KERNEL_SERVICES_MIB_NICE    ".1.3.6.1.3.400.1.1.3"
#define KERNEL_SERVICES_MIB_GETGID	".1.3.6.1.3.400.1.1.4"
#define KERNEL_SERVICES_MIB_GETUID	".1.3.6.1.3.400.1.1.5"
#define KERNEL_SERVICES_MIB_GETEUID	".1.3.6.1.3.400.1.1.6"
#define KERNEL_SERVICES_MIB_GETSID	".1.3.6.1.3.400.1.1.7"
#define KERNEL_SERVICES_MIB_SETSID	".1.3.6.1.3.400.1.1.8"
#define KERNEL_SERVICES_MIB_GETPGID	".1.3.6.1.3.400.1.1.9"
//kernel/process
#define KERNEL_SERVICES_MIB_FORK	".1.3.6.1.3.400.1.2.1"
#define KERNEL_SERVICES_MIB_IDLE	".1.3.6.1.3.400.1.2.2"
#define KERNEL_SERVICES_MIB_VFORK	".1.3.6.1.3.400.1.2.3"
//fs
#define KERNEL_SERVICES_MIB_OPEN	".1.3.6.1.3.400.1.3.1"
#define KERNEL_SERVICES_MIB_CREAT   ".1.3.6.1.3.400.1.3.2"  
#define KERNEL_SERVICES_MIB_RENAME  ".1.3.6.1.3.400.1.3.3"  
#define KERNEL_SERVICES_MIB_MKDIR   ".1.3.6.1.3.400.1.3.4"     
#define KERNEL_SERVICES_MIB_RMDIR   ".1.3.6.1.3.400.1.3.5"     
#define KERNEL_SERVICES_MIB_CHDIR   ".1.3.6.1.3.400.1.3.6" 
#define KERNEL_SERVICES_MIB_LINK	".1.3.6.1.3.400.1.3.7"
#define KERNEL_SERVICES_MIB_UNLINK	".1.3.6.1.3.400.1.3.8"
#define KERNEL_SERVICES_MIB_CHMOD	".1.3.6.1.3.400.1.3.9"
#define KERNEL_SERVICES_MIB_ACCESS	".1.3.6.1.3.400.1.3.10"
//kernel/signal
#define KERNEL_SERVICES_MIB_KILL    ".1.3.6.1.3.400.1.4.1" 
//kernel/sys
#define KERNEL_SERVICES_MIB_REBOOT  ".1.3.6.1.3.400.1.5.1" 
#define KERNEL_SERVICES_MIB_PAUSE	".1.3.6.1.3.400.1.5.2"    
//kernel/time
#define KERNEL_SERVICES_MIB_TIME    ".1.3.6.1.3.400.1.7.1" 

//change
#define KERNEL_SERVICES_MIB_OPEN_FILE_NAME		".1.3.6.1.3.400.1.3.1.1"
#define KERNEL_SERVICES_MIB_OPEN_FLAGS			".1.3.6.1.3.400.1.3.1.2"
#define KERNEL_SERVICES_MIB_CREAT_FILE_NAME	    ".1.3.6.1.3.400.1.3.2,1" 
#define KERNEL_SERVICES_MIB_CREAT_MODE	   		".1.3.6.1.3.400.1.3.2,2" 



struct snmp_field {
  u_char type;
  u_char length;
  u_char value[128];  // I chose 128 because it's the maximum oid size, might need to change it
};