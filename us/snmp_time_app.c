#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	int i;
	long mytime, ttime;

	mytime = snmp_time(NULL);
	if (mytime < 0)
	{
		perror("snmp_time");
		exit(1);
	}

	printf("time from snmp_time() is %d\n", mytime);


	ttime = time(NULL);

	printf("time from time() is %d\n", ttime);


	return 0;
}
