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

	/*-------------------------------open------------------------------------*/
	// fd = open("test.txt", O_RDWR);
	// printf("open fd: %d \n", fd);
	// need to send the full path
	// mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	mode_t mode = S_IRUSR;
	fd = snmp_chmod("/home/frida/Guang/test2.txt", strlen("/home/frida/Guang/test2.txt"), mode);

	if (fd < 0) {
		perror("chmod");
		exit(1);
	}
	printf("chmod fd: %d \n", fd);

	
	return 0;
}
