#include <linux/types.h>

typedef u_short oid; // taken from <net-snmp/library/oid.h> but I modified it into short
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

// from include/net-snmp/library/snmp.h
#define SNMP_VERSION_1      0
#define SNMP_VERSION_2c     1
#define SNMP_VERSION_3      3
#define SNMP_MSG_GET    ((u_char)160)
#define SNMP_MSG_GETNEXT  161
#define SNMP_MSG_RESPONSE   162
#define SNMP_MSG_SET    163

#define KERNEL_SERVICES_MIB_GETPID_OID ".1.3.6.1.3.400.1.1.1"

struct snmp_field {
  u_char type;
  u_char length;
  u_char value[128];  // I chose 128 because it's the maximum oid size, might need to change it
};