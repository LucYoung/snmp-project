// define oids for the kernel mib
#define CSUF_PEN		 400    // replace with our assigned number from IANA
#define KERNEL_SERVICES_MIB	 1  //.1.3.6.1.3.400.1
// subsystems definition
#define SCHED_SUBSYSTEM	 	 1  //.1.3.6.1.3.400.1.1 (scheduling)
#define PM_SUBSYSTEM		 2	//.1.3.6.1.3.400.1.2 (process management)
#define FS_SUBSYSTEM 		 3  //.1.3.6.1.3.400.1.3 (file system)
#define SIGNAL_SUBSYSTEM	 4  //.1.3.6.1.3.400.1.4 (kernel/signal)
#define SYS_SUBSYSTEM		 5  //.1.3.6.1.3.400.1.5 (sys)
#define EXIT_SUBSYSTEM		 6	//.1.3.6.1.3.400.1.6 (exit)
#define TIME_SUBSYSTEM		 7	//.1.3.6.1.3.400.1.7 (time)
// system calls definitions
//kernel/sched
#define KERNEL_SERVICES_MIB_GETPID	1  	//.1.3.6.1.3.400.1.1.1
#define KERNEL_SERVICES_MIB_GETPPID 2	//.1.3.6.1.3.400.1.1.2
#define KERNEL_SERVICES_MIB_NICE    3	//.1.3.6.1.3.400.1.1.3
#define KERNEL_SERVICES_MIB_GETGID  4	//.1.3.6.1.3.400.1.1.4
#define KERNEL_SERVICES_MIB_GETUID  5	//.1.3.6.1.3.400.1.1.5
#define KERNEL_SERVICES_MIB_GETEUID 6	//.1.3.6.1.3.400.1.1.6
#define KERNEL_SERVICES_MIB_GETSID  7	//.1.3.6.1.3.400.1.1.7
#define KERNEL_SERVICES_MIB_SETSID  8	//.1.3.6.1.3.400.1.1.8
#define KERNEL_SERVICES_MIB_GETPGID 9	//.1.3.6.1.3.400.1.1.9
//kernel/process
#define KERNEL_SERVICES_MIB_FORK	1 	//.1.3.6.1.3.400.1.2.1
#define KERNEL_SERVICES_MIB_IDLE	2 	//.1.3.6.1.3.400.1.2.2
#define KERNEL_SERVICES_MIB_VFORK 	3	//.1.3.6.1.3.400.1.2.3
//fs
#define KERNEL_SERVICES_MIB_OPEN	1	//".1.3.6.1.3.400.1.3.1"
#define KERNEL_SERVICES_MIB_CREAT   2	//".1.3.6.1.3.400.1.3.2"  
#define KERNEL_SERVICES_MIB_RENAME  3	//".1.3.6.1.3.400.1.3.3"  
#define KERNEL_SERVICES_MIB_MKDIR   4 	//".1.3.6.1.3.400.1.3.4"     
#define KERNEL_SERVICES_MIB_RMDIR   5 	//".1.3.6.1.3.400.1.3.5"     
#define KERNEL_SERVICES_MIB_CHDIR   6 	//".1.3.6.1.3.400.1.3.6" 
#define KERNEL_SERVICES_MIB_LINK    7 	//".1.3.6.1.3.400.1.3.7" 
#define KERNEL_SERVICES_MIB_UNLINK  8 	//".1.3.6.1.3.400.1.3.8" 
#define KERNEL_SERVICES_MIB_CHMOD   9 	//".1.3.6.1.3.400.1.3.9" 
#define KERNEL_SERVICES_MIB_ACCESS  10	//".1.3.6.1.3.400.1.3.10" 
//kernel/signal
#define KERNEL_SERVICES_MIB_KILL    1 	//".1.3.6.1.3.400.1.4.1" 
//kernel/sys
#define KERNEL_SERVICES_MIB_REBOOT  1	//".1.3.6.1.3.400.1.5.1" 
#define KERNEL_SERVICES_MIB_PAUSE   2	//".1.3.6.1.3.400.1.5.2"    
//kernel/time
#define KERNEL_SERVICES_MIB_TIME    1	//".1.3.6.1.3.400.1.7.1" 
//no need to specific this
#define KERNEL_SERVICES_MIB_OPEN_FILE_NAME	1	// ".1.3.6.1.3.400.1.3.1.1"
#define KERNEL_SERVICES_MIB_OPEN_FLAGS		2	// ".1.3.6.1.3.400.1.3.1.2"





