#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>

//Parent process
int main()
{
pid_t  pid;
	/* fork another process */
	pid = syscall(545, 777);
	if (pid < 0) { /* error occurred */
		printf("Fork Failed \n");
		exit(-1);
	}
	else if (pid == 0) { /* child process */
		execlp("/bin/ls", "ls", NULL);
	}
	else { /* parent process */
	/* parent will wait for the child to complete */
		wait (NULL);
		printf ("Child Complete\n");
		exit(0);
	}
}

