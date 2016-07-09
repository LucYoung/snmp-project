// testing custom system calls

#include <linux/kernel.h>
#include <linux/syscalls.h>

asmlinkage long sys_hello( netsnmp_pdu* pdu) {
	//int i;
	netsnmp_variable_list *vars;
	long retval = 0;
	switch (pdu->command) {
	  case 160: // get request
	    printk("snmp kernel: received snmp get request \n");
	    for (vars = pdu->variables; vars; vars = vars->next_variable) {
	      oid* myOID = vars->name;
	      //for (i = 0; i < vars->name_length; i++) {
		//printk(" snmp kernel: oid = %d \n", myOID[i]);
		if (myOID[5] == CSUF_PEN && myOID[6] == KERNEL_SERVICES_MIB) {
		  // myOID[7] is the kernel subsystem, myOID[8] is the service
		  switch (myOID[7]) {
		    case KERNEL_SUBSYSTEM:
		      printk("snmp kernel: kernel main service requested \n");
		      switch (myOID[8]) {
			case KERNEL_SERVICES_MIB_GETPID:
			  printk("snmp kernel: getpid \n");
			  retval = sys_getpid();
		      }
		      break;
		    case FS_SUBSYSTEM:
		      break;
		    case NET_SUBSYSTEM:
		      break;
 
		  }  
		} else {
		  printk("snmp kernel: unrecognized oid \n");
		}

	      //}
	    }
	    break;
	  /* only handling get requests for now
	    
	  case 161: // getnext request
	  case 162: // snmp_msg_response
	  case 163: // set request 
	   */
	}
	
	return retval;
}
