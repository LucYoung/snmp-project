#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	
	int i = 0;
	while(i<100)
	{
		printf("%d\n", i);
		if (i == 5)
		{
			snmp_pause();
		}
		i++;
	}


	return 0;
}
