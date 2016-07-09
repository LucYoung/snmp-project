#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"

int main(int argc, char const *argv[]) {
	printf("%d\n", getpriority());
	printf("%d\n", snmp_nice(-3));

	return 0;
}
