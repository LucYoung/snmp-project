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
	
	fd = snmp_rmdir("/home/frida/Guang/test2", strlen("/home/frida/Guang/test2"));

	if (fd < 0) {
		perror("rmdir");
		exit(1);
	}
	printf("rmdir fd: %d \n", fd);

	
	return 0;
}
