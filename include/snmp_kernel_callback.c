// contains the callback functions invoked when a service is requested using an snmp message
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>



long snmp_getpid_callback(void) {
	return sys_getpid();
}
long snmp_getppid_callback(void) {
    return sys_getppid();
}

long snmp_fork_callback(void) {
	return sys_fork();
}
long snmp_vfork_callback(void) {
    return sys_vfork();
}
long snmp_getsid_callback(pid_t pid){
    return sys_getsid(pid);
}
long snmp_setsid_callback(void){
    return sys_setsid();
}
long snmp_getpgid_callback(pid_t pid){
    return sys_getpgid(pid);
}

long snmp_nice_callback(int inc) {
    return sys_nice(inc);
}
long snmp_kill_callback(pid_t pid, int sig){
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_kill(pid, sig);

    set_fs(old_fs);

    return retval;
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

long snmp_creat_callback(u_char *filename, mode_t mode) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_creat( (char *) filename, mode);


    set_fs(old_fs);

    return retval;
}
long snmp_access_callback(u_char *filename, mode_t mode) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_access( (char *) filename, mode);


    set_fs(old_fs);

    return retval;
}
long snmp_time_callback(void){
    return sys_time(NULL);
}

long snmp_mkdir_callback(u_char *filename, mode_t mode) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_mkdir( (char *) filename, mode);


    set_fs(old_fs);

    return retval;
}

long snmp_rmdir_callback(u_char *filename) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_rmdir( (char *) filename);


    set_fs(old_fs);

    return retval;
}

long snmp_rename_callback(u_char *filename1, u_char *filename2) {
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_rename((char *) filename1,(char *) filename2);


    set_fs(old_fs);

    return retval;
}
long snmp_link_callback(u_char* oldpath, u_char* newpath){
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_link((char *) oldpath, (char *) newpath);


    set_fs(old_fs);

    return retval;
}
long snmp_unlink_callback(u_char* path)
{
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_unlink( (char *) path);


    set_fs(old_fs);

    return retval;
}
long snmp_pause_callback(void){
    return sys_pause();
}
long snmp_getgid_callback(void){
    return sys_getgid();
}
long snmp_getuid_callback(void){
    return sys_getuid();
}
long snmp_geteuid_callback(void){
    return sys_geteuid();
}
long snmp_chdir_callback(u_char* path){
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_chdir( (char *) path);


    set_fs(old_fs);

    return retval;
}
long snmp_chmod_callback(u_char* path, mode_t mode){
    long retval;
    mm_segment_t old_fs;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    retval = sys_chmod( (char *) path, mode);


    set_fs(old_fs);

    return retval;
}

EXPORT_SYMBOL(snmp_getpid_callback);
EXPORT_SYMBOL(snmp_getppid_callback);
EXPORT_SYMBOL(snmp_fork_callback);
EXPORT_SYMBOL(snmp_open_callback);
EXPORT_SYMBOL(snmp_time_callback);
EXPORT_SYMBOL(snmp_creat_callback);
EXPORT_SYMBOL(snmp_mkdir_callback);
EXPORT_SYMBOL(snmp_rmdir_callback);
EXPORT_SYMBOL(snmp_geteuid_callback);
EXPORT_SYMBOL(snmp_getuid_callback);
EXPORT_SYMBOL(snmp_getgid_callback);
EXPORT_SYMBOL(snmp_pause_callback);
EXPORT_SYMBOL(snmp_chmod_callback);
EXPORT_SYMBOL(snmp_chdir_callback);
EXPORT_SYMBOL(snmp_unlink_callback);
EXPORT_SYMBOL(snmp_getsid_callback);
EXPORT_SYMBOL(snmp_setsid_callback);
EXPORT_SYMBOL(snmp_getpgid_callback);

EXPORT_SYMBOL(snmp_access_callback);
EXPORT_SYMBOL(snmp_kill_callback);
EXPORT_SYMBOL(snmp_nice_callback);
//--------------------working on---------------------

EXPORT_SYMBOL(snmp_rename_callback);
EXPORT_SYMBOL(snmp_link_callback);
EXPORT_SYMBOL(snmp_vfork_callback);

