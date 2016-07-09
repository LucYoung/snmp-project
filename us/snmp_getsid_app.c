#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {

	printf("pid from snmp_getsid() %d\n", snmp_getsid(getpid()));
	printf("pid from getsid() %d\n", snmp_getsid(getpid()));


	return 0;
}
