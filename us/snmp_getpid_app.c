#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	int i;
	pid_t pid, mypid;

	mypid = snmp_getpid();

	printf("pid from snmp_getpid is %d\n", mypid);

	pid = getpid();

	printf("pid from getpid is %d\n", pid);


	return 0;
}
