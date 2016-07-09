#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	printf("uid from snmp_geteuid()%d\n", snmp_geteuid());


	return 0;
}
