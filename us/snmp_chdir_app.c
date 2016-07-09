#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "snmp_lib.h"

int main(int argc, char const *argv[]) {

	char cwd[50];
	getcwd(cwd, sizeof(cwd));
	printf("%s\n", cwd);

	snmp_chdir("/home/frida/",strlen("/home/frida/"));

	// int status = snmp_chdir("/home/frida/");
	// if (status<0)
	// {
	// 	perror("snmp_chdir");
	// 	exit(1);
	// }

	getcwd(cwd, sizeof(cwd));
	printf("%s\n", cwd);


	
	return 0;
}
