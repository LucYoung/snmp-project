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
	fd = snmp_open("/home/frida/test.txt", strlen("/home/frida/test.txt"), O_RDWR);

	if (fd < 0) {
		perror("open");
		exit(1);
	}
	printf("fd: %d \n", fd);

	int pid = getpid();

	printf("pid: %d \n", pid);

	close(fd);
	
	return 0;
}
