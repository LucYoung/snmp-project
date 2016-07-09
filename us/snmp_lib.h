#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "types.h"


void decode_oid(unsigned char* en_oid, size_t en_oid_len, oid* dec_oid, size_t *dec_oid_len);
// library to encode an snmp message and its required fields based on the Basic Encoding Rules (BER) for snmp messages
// main source of information is http://www.rane.com/note161.html

// encode oid
void encode_oid(oid *oid_arr, size_t oid_arr_len, u_char* en_oid, size_t *en_oid_len);

void encode_get_request(u_char* message, size_t* message_len, oid* a_oid, size_t a_oid_len);

// construct a get response for getpid, for testing purposes
void construct_get_response(struct snmp_field *recv_message);

void decode_get_response(struct snmp_field *recv_message, pid_t *ret_pid);

void decode_get_response_long(struct snmp_field *recv_message, long *ret_long);

pid_t snmp_getpid();
pid_t snmp_getppid();
gid_t snmp_getgid();
uid_t snmp_getuid();
uid_t snmp_geteuid();
pid_t snmp_setsid();
pid_t snmp_getsid(pid_t pid);
pid_t snmp_getpgid(pid_t pid);

pid_t snmp_fork();
pid_t snmp_fork();

void encode_varbind(struct snmp_field *a_varbind, oid* a_oid, size_t a_oid_len, u_char *value, u_char value_type, size_t fn_len);

void encode_get_request_with_params(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, u_char *value1, size_t fn_len, oid* param2, size_t param2_len, int value2);

void encode_get_request_with_param_int(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, int value1, size_t fn_len);

void encode_get_request_with_param_int_int(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, int value1, size_t fn_len, oid* param2, size_t param2_len, int value2);


int snmp_open(u_char *filename, size_t fn_len, int flags);

int snmp_creat(u_char *filename, size_t fn_len, mode_t mode);

int snmp_access(u_char *filename, size_t fn_len, mode_t mode);

int snmp_chmod(u_char *filename, size_t fn_len, mode_t mode);

int snmp_mkdir(u_char *filename, size_t fn_len, mode_t mode);

int snmp_unlink(u_char *filename, size_t fn_len);

int snmp_rmdir(u_char *filename, size_t fn_len);

int snmp_read(int fd, char* buf, size_t buf_len);

int snmp_exit(int status);

int snmp_nice(int inc);

int snmp_pause();

int snmp_kill(pid_t pid, int sig);

long snmp_time();
// encode_message: type:sequence, length: total length of the message, its value: whole message
// void encode_message(u_char* message, size_t* message_len);

// encode_version: type, integer, length: 1, value : 0, 1, 3 for v1, v2c,v3
// encode_community: type: octet string, length: length of the string, value: configured community
/* encode_pdu: type: getrequest, setrequest, getresponse
 1- request id: An Integer that identifies a particular SNMP request. This index is echoed back in the response from the SNMP agent, allowing the SNMP manager to match an incoming response to the appropriate request.

 2- error
 3- error index
 4- varbind list: contains list of varbind
 	each varbind has object identifider (oid) and the value

*/
// encode_oid

// also need to add methods to decode them

int snmp_close(int fd);

//int snmp_read(int fd, char* buf, size_t buf_len)

//int snmp_write();
