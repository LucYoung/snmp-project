#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {


	printf("Pid from the Parent %d\n", getpid());

	pid_t pid = snmp_fork();

	printf("Child Pid from snmp_fork() %d\n", pid);

	return 0;
}
