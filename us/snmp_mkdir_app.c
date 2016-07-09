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
	mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	// mode_t mode = S_IRUSR;
	fd = snmp_mkdir("/home/frida/Guang/test2", strlen("/home/frida/Guang/test2"), mode);

	if (fd < 0) {
		perror("creat");
		exit(1);
	}
	printf("mkdir fd: %d \n", fd);

	
	return 0;
}
