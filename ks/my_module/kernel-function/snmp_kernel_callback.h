long snmp_pid_callback(void);
long snmp_fork_callback(void);
long snmp_open_callback(u_char *filename, int flags);
long snmp_close_callback(int fd);
long snmp_read_callback(int fd, char* buff, size_t);
long snmp_write_callback(int fd, char* buff, size_t);