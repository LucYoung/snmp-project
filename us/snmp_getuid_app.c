#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	printf("uid from snmp_getuid()%d\n", snmp_getuid());


	return 0;
}
