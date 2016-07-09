#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>


int main() {
	int i;
	pid_t mypid;
	for(i = 0; i <= 10000; i++) {
		mypid = getpid();
	}  

  return 0;
}


