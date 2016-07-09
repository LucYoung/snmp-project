#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	printf("pid from snmp_getpgid() %d\n", snmp_getpgid(getpid()));
	printf("pid from getpgid() %d\n", snmp_getpgid(getpid()));


	return 0;
}
