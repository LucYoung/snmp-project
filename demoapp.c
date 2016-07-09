#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KERNEL_SERVICES_MIB_GETPID ".1.3.6.1.3.400.1.1.1"
#define TEST_MIB ".1.3.6.1.2.1.1.1.0"
int main(int argc, char ** argv)
{
    netsnmp_pdu *pdu;

    oid anOID[MAX_OID_LEN];
    size_t anOID_len;

    netsnmp_variable_list *vars;
   

    /*
     * Initialize the SNMP library
     */
    init_snmp("demoapp");
    
     
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    anOID_len = MAX_OID_LEN;
    if (!snmp_parse_oid(KERNEL_SERVICES_MIB_GETPID, anOID, &anOID_len)) {
      snmp_perror(KERNEL_SERVICES_MIB_GETPID);     
      exit(1);
    }
    
    snmp_add_null_var(pdu, anOID, anOID_len);
    
     printf("testing system call\n");
     long int test = syscall(545, pdu); 
     printf("my system call returned %ld \n", test);
     
     snmp_free_pdu(pdu);
     return (0);
} /* main() */
