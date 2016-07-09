#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"

int main(int argc, char const *argv[]) {
	int fd, nread, nwrite;
	long cfd;
	char buffer[50];
	size_t buff_len;


	fd = snmp_unlink("/home/frida/Guang/test2.txt", strlen("/home/frida/Guang/test2.txt"));

	if (fd < 0) {
		perror("unlink");
		exit(1);
	}
	printf("unlink fd: %d \n", fd);

	
	return 0;
}
