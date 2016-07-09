#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"

int main(int argc, char const *argv[]) {
	// mode_t mode = F_OK;
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	int fd = snmp_access("/home/frida/Guang/test.txt",strlen("/home/frida/Guang/test.txt"),mode);
	// if (fd < 0) {
	// 	perror("access");
	// 	exit(1);
	// }
	// mode = (mode_t) fd;
	printf("snmp_access() %d\n", fd);
	printf("access() %d\n", access("/home/frida/Guang/test.txt",mode));

	
	return 0;
}
