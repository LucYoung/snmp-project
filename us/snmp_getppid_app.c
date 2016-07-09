#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	pid_t pid, snmpppid;
	pid = fork();
	if (pid==0)
	{
		printf("ppid from getppid() %d\n", getppid());
		snmpppid = snmp_getppid();
		if (snmpppid < 0)
		{
			perror("snmp_getppid");
			exit(1);
		}
		printf("ppid from snmp_getppid() %d\n", snmp_getppid());
	}
	else
	{
		wait();
		printf("the parent pid from getpid() %d\n", getpid());
	}


	return 0;
}
