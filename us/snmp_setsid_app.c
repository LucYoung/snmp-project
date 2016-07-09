#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	printf("pid from snmp_setsid() %d\n", snmp_setsid());
	printf("pid from setsid() %d\n", setsid());


	return 0;
}
