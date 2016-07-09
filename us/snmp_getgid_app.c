#include <stdio.h>
#include <stdlib.h>
#include "snmp_lib.h"

int main() {
	printf("gid from snmp_getgid()%d\n", snmp_getgid());


	return 0;
}
