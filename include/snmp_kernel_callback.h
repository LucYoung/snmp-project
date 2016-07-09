long snmp_getppid_callback(void);
long snmp_getpid_callback(void);
long snmp_fork_callback(void);
long snmp_open_callback(u_char *filename, int flags);
long snmp_creat_callback(u_char *filename, mode_t mode);
long snmp_time_callback(void);
long snmp_mkdir_callback(u_char *filename, mode_t mode);
long snmp_rmdir_callback(u_char *filename);
long snmp_chmod_callback(u_char* path, mode_t mode);
long snmp_unlink_callback(u_char* path);
long snmp_pause_callback(void);
long snmp_getgid_callback(void);
long snmp_getuid_callback(void);
long snmp_geteuid_callback(void);
long snmp_chdir_callback(u_char* path);
long snmp_getsid_callback(pid_t pid);
long snmp_setsid_callback(void);
long snmp_getpgid_callback(pid_t pid);

long snmp_access_callback(u_char *filename, mode_t mode);
long snmp_nice_callback(int inc);
long snmp_kill_callback(pid_t pid, int sig);
//-------------------working on-------------------------
long snmp_rename_callback(u_char *filename1, u_char *filename2);
long snmp_link_callback(u_char* oldpath, u_char* newpath);
long snmp_idle_callback(void);
long snmp_vfork_callback(void);





