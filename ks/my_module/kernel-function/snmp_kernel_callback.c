// contains the callback functions invoked when a service is requested using an snmp message
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/export.h>




long snmp_pid_callback(void) {
	return sys_getpid();
}

long snmp_fork_callback(void) {
	return sys_fork();
}

long snmp_open_callback(u_char *filename, int flags) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_open( (char *) filename, flags, 0644);

    set_fs(old_fs);

    return retval;
}
long snmp_close_callback(int fd){
	long retval;
	mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

	retval = sys_close(fd);

	set_fs(old_fs);

	return retval;
}
long snmp_read_callback(int fd, char *buff,size_t size) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_read(fd, buff, size);

    set_fs(old_fs);

    return retval;
}



EXPORT_SYMBOL(snmp_pid_callback);
EXPORT_SYMBOL(snmp_fork_callback);
EXPORT_SYMBOL(snmp_open_callback);
EXPORT_SYMBOL(snmp_close_callback);
EXPORT_SYMBOL(snmp_read_callback);
