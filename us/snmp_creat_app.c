#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"

int main(int argc, char const *argv[]) {
	int fd;

	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	printf("mode %d\n", mode);
	// mode_t mode = S_IRUSR;
	fd = snmp_creat("/home/frida/Guang/test2.txt", strlen("/home/frida/Guang/test2.txt"), mode);

	if (fd < 0) {
		perror("creat");
		exit(1);
	}
	printf("creat fd: %d \n", fd);

	
	return 0;
}
