#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"
#include <signal.h>

int main(int argc, char const *argv[]) {
	
	printf("The process is running at Pid =%d\n", getpid());

	printf("%d\n", snmp_kill(getpid(),SIGUSR1));
	sleep(1000);	

	return 0;
}
