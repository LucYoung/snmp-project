#include "snmp_lib.h"

// source for the encoding rules http://www.rane.com/note161.html
void decode_oid(unsigned char* en_oid, size_t en_oid_len, oid* dec_oid, size_t *dec_oid_len) {
	int i;
	// first byte represents .1.3
	if (en_oid[0] == 43){
		dec_oid[0] = 1;
		dec_oid[1] = 3;
	}
	int dec_oid_index = 2;
	// next we check if the higher most bit is set in each byte
	// if it is then it means the oid > 255 and it is encoded using two bytes
	for (i = 1; i < en_oid_len; i++) {
		if ((en_oid[i] >> 7) == 1) {
			dec_oid[dec_oid_index] = (en_oid[i] & 127 )*128 + (en_oid[i+1] & 127);
			dec_oid_index++;
			i++;			
		} else {
			dec_oid[dec_oid_index] = en_oid[i];
			dec_oid_index++;
		}
	}
	*dec_oid_len = dec_oid_index;
}


/* encoding the oid based on BER rules for oid
 * takes an array of the oid values in format: {1,3,6,1,3,400,1,1,1}; 
 * and stores the result in en_oid
*/
void encode_oid(oid *oid_arr, size_t oid_arr_len, u_char* en_oid, size_t *en_oid_len) {
	int i;
	size_t res_len = 0;
	
	// first two oids .1.3 will be encoded in one byte
	en_oid[0] = 40*oid_arr[0] + oid_arr[1];	
	res_len++;	
	// if the oid is greater than 255, it will be encoded in multiple bytes
	// set the MSB of first byte and copy the value in the remaining 7 bits of each byte
	for (i = 2; i < oid_arr_len; i++) {
        // printf("oid at %d : %d \n", i, oid_arr[i]);
		if (oid_arr[i] > 255) {
			en_oid[res_len] = (oid_arr[i] >> 7) | 128;
			res_len++;
			en_oid[res_len] = (oid_arr[i] & 0xFE) & 127 ;
			res_len++;			
		} else {
			// copy the value as is
			en_oid[res_len] = oid_arr[i];
			res_len++;
		}
	}
	*en_oid_len = res_len;
    
}

void encode_varbind(struct snmp_field *a_varbind, oid* a_oid, size_t a_oid_len, u_char *value, u_char value_type, size_t fn_len) {
    struct snmp_field object_id;
    struct snmp_field obj_val;

    u_char en_oid[128];
    size_t en_oid_len;   
    

    encode_oid(a_oid, a_oid_len, en_oid, &en_oid_len);    

    object_id.type = ASN_OBJECT_ID;
    object_id.length = en_oid_len;
    memcpy(object_id.value, en_oid, object_id.length);
    
    obj_val.type = value_type;
    
    if (value_type == ASN_NULL) {
        obj_val.length = 0;
        memset(obj_val.value, 0x00,128);  
    } else if (value_type == ASN_OCTET_STR) {
        obj_val.length = fn_len;
        strncpy(obj_val.value, value, fn_len);

    } else if (value_type == ASN_INTEGER) {
        obj_val.length = fn_len;
        int int_val;
        memcpy(&int_val, (int*) value, sizeof(int));
        u_int32_t n_int_val = htonl(int_val);
        memcpy(obj_val.value, &n_int_val, fn_len);
       
    }

       
    a_varbind->type = ASN_OPAQUE_TAG2; // sequence
    a_varbind->length = object_id.length + 2 + obj_val.length + 2;
    
    memset(a_varbind->value, 0, a_varbind->length);
    memcpy(a_varbind->value, &object_id, object_id.length+2);    
    memcpy((a_varbind->value + object_id.length+2), &obj_val, obj_val.length + 2);    

    
}



/* constructs a get-request snmp message with one varbind object
 * params:
 * message: message buffer to store the result
 * message_len: length of the resulting snmp message
 * a_oid: the oid of the requested service, in the form {1,3,6,1,3,400,1,1,1}
 * a_oid_len: length of the array
 * this function can be modified to construct other types of snmp messages by modifying request.type 
 * it can also be extended to support multiple varbind objects
 * note: the lengths are very crucial to constructing a proper message, so have to pay close attention to them
 * fields: 
 * 1- header consists of the version and community string
 * 2- request PDU consists of request ID, error, error index, varbind list 
 * 3- varbind list consists of one or more varbind
 * 4- varbind consists of object ID and its value
 * Note: to figure out the length of each field, it's better to work backwards
*/
void encode_get_request(u_char* message, size_t* message_len, oid* a_oid, size_t a_oid_len) {
	struct snmp_field snmp_message;
	struct snmp_field version;
	struct snmp_field community;
	struct snmp_field request;
	struct snmp_field request_id;
	struct snmp_field error;
	struct snmp_field error_index;
	struct snmp_field varbind_list;
	struct snmp_field a_varbind; 
    // struct snmp_field object_id;
    // struct snmp_field obj_val;

    // u_char en_oid[128];
    // size_t en_oid_len;
	
	size_t req_length = 0;
	size_t header_len = 0;
	size_t offset = 0;   
    
    encode_varbind(&a_varbind, a_oid, a_oid_len, NULL, ASN_NULL, 0);    
    
    req_length += a_varbind.length + 2;

    varbind_list.type = ASN_OPAQUE_TAG2; // sequence
    varbind_list.length = a_varbind.length + 2;
    
    memcpy(varbind_list.value, &a_varbind, a_varbind.length+2);

    req_length += 2;
    
    error_index.type = ASN_INTEGER;
    error_index.length = 1;
    u_char e_val = 0;    
    strncpy(error_index.value, &e_val, 1);

    req_length += error_index.length +2;
    
    error.type = ASN_INTEGER;
    error.length = 1;    
    strncpy(error.value, &e_val, 1);

    req_length += error.length +2;
    
    request_id.type = ASN_INTEGER;
    request_id.length = sizeof(u_int16_t);
    u_int16_t req_val = htons(rand());
    // printf("request is %d \n", ntohs(req_val));
    strncpy(request_id.value, (u_char*)&req_val, sizeof(u_int16_t));

    req_length += request_id.length+2;

    request.type = SNMP_MSG_GET;
    request.length = req_length;    
    
    offset += request_id.length+2;    
    memcpy(request.value, &request_id,request_id.length+2);    
    memcpy(request.value+offset, &error,error.length+2);    
    offset += error.length+ 2;   
    memcpy(request.value+offset, &error_index,error_index.length+2);
    offset += error_index.length+ 2;    
    memcpy(request.value+offset, &varbind_list,varbind_list.length+2);

    req_length += 2;
    
    community.type = ASN_OCTET_STR;
    community.length = (u_char)strlen("public");
    strncpy(community.value, "public", strlen("public")+1);    
    header_len += community.length+2;
  
    version.type = ASN_INTEGER;
    version.length = 1;    
    u_char v_value = SNMP_VERSION_2c;
    strncpy(version.value, &v_value, 1);

    header_len += version.length+2;
    
    snmp_message.type = ASN_OPAQUE_TAG2; 
    snmp_message.length = req_length+header_len;
    memset(snmp_message.value, 0x00, snmp_message.length);

    memcpy(snmp_message.value, &version, sizeof(version));
    memcpy((snmp_message.value +version.length+2), &community, community.length+2);   
    
    memcpy((snmp_message.value + header_len), &request, req_length+2);
    *message_len = snmp_message.length+2;
    memcpy(message, &snmp_message, snmp_message.length+2);

}

int decode_varbind(struct snmp_field *vb, u_char *param_val) {
    struct snmp_field *vb_oid;
    struct snmp_field *vb_val;   

    vb_oid = (struct snmp_field *) (vb->value);

    vb_val = (struct snmp_field *) (vb->value + vb_oid->length + 2);    
    
    memcpy(param_val, vb_val->value, vb_val->length);

    return vb_val->length;    
    
}

// encodes a get request with two parameters
void encode_get_request_with_params(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, u_char *value1, size_t fn_len, oid* param2, size_t param2_len, int value2) {
    struct snmp_field snmp_message;
    struct snmp_field version;
    struct snmp_field community;
    struct snmp_field request;
    struct snmp_field request_id;
    struct snmp_field error;
    struct snmp_field error_index;
    struct snmp_field varbind_list;
    struct snmp_field service_varbind;
    struct snmp_field param1_varbind;
    struct snmp_field param2_varbind;
    
    
    size_t req_length = 0;
    size_t header_len = 0;
    size_t offset = 0;   
    
    encode_varbind(&service_varbind, service, service_len, NULL, ASN_NULL, 0);

    encode_varbind(&param1_varbind, param1, param1_len, value1, ASN_OCTET_STR, fn_len);

    encode_varbind(&param2_varbind, param2, param2_len, (u_char*)&value2, ASN_INTEGER, sizeof(int));    
    
    // u_char param1_val[50];
    // u_char param2_val[10];
    // size_t p1_val_len, p2_val_len;
    
    // p1_val_len = decode_varbind(&param1_varbind, param1_val);
    // printf("param_val %s \n", param1_val);
    // printf("p1_val_len %d \n", p1_val_len);
    // param1_val[p1_val_len] = '\0';

    // printf("param_val %s \n", param1_val);



    // p2_val_len = decode_varbind(&param2_varbind, param2_val);
    // printf("p2_val_len %d \n", p2_val_len);

    // u_int32_t n_int_val;
    // int param_int;
    // memcpy(&n_int_val, param2_val, p2_val_len);
    // param_int = ntohl(n_int_val);

    // printf("param_int: %d \n", param_int);

    req_length += service_varbind.length + 2 + param1_varbind.length + 2 + param2_varbind.length + 2;

    varbind_list.type = ASN_OPAQUE_TAG2; // sequence
    varbind_list.length = req_length;

    offset = service_varbind.length+2;
    
    memcpy(varbind_list.value, &service_varbind, service_varbind.length+2);

    
    memcpy((varbind_list.value + offset), &param1_varbind, param1_varbind.length+2);
    offset += param1_varbind.length+2;

    memcpy((varbind_list.value + offset), &param2_varbind, param2_varbind.length+2);

    offset = 0;
    req_length += 2;
    
    error_index.type = ASN_INTEGER;
    error_index.length = 1;
    u_char e_val = 0;    
    strncpy(error_index.value, &e_val, 1);

    req_length += error_index.length +2;

    
    error.type = ASN_INTEGER;
    error.length = 1;    
    strncpy(error.value, &e_val, 1);

    req_length += error.length +2;

    request_id.type = ASN_INTEGER;
    request_id.length = sizeof(u_int16_t);
    u_int16_t req_val = htons(rand());
    // printf("request is %d \n", ntohs(req_val));
    strncpy(request_id.value, (u_char*)&req_val, sizeof(u_int16_t));

    req_length += request_id.length+2;
    request.type = SNMP_MSG_GET;
    request.length = req_length;    
    
    offset += request_id.length+2;    
    memcpy(request.value, &request_id,request_id.length+2);    
    memcpy(request.value+offset, &error,error.length+2);    
    offset += error.length+ 2;   
    memcpy(request.value+offset, &error_index,error_index.length+2);
    offset += error_index.length+ 2;    
    memcpy(request.value+offset, &varbind_list,varbind_list.length+2);

    req_length += 2;
    
    community.type = ASN_OCTET_STR;
    community.length = (u_char)strlen("public");
    strncpy(community.value, "public", strlen("public")+1);    
    header_len += community.length+2;
  
    version.type = ASN_INTEGER;
    version.length = 1;    
    u_char v_value = SNMP_VERSION_2c;
    strncpy(version.value, &v_value, 1);

    header_len += version.length+2;
    
    snmp_message.type = ASN_OPAQUE_TAG2; 
    snmp_message.length = req_length+header_len;
    memset(snmp_message.value, 0x00, snmp_message.length);

    memcpy(snmp_message.value, &version, sizeof(version));
    memcpy((snmp_message.value +version.length+2), &community, community.length+2);   
    
    memcpy((snmp_message.value + header_len), &request, req_length+2);
    *message_len = snmp_message.length+2;
    memcpy(message, &snmp_message, snmp_message.length+2);
    
}
// encodes a get request with one int parameter
void encode_get_request_with_param_int(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, int value1, size_t fn_len) {
    struct snmp_field snmp_message;
    struct snmp_field version;
    struct snmp_field community;
    struct snmp_field request;
    struct snmp_field request_id;
    struct snmp_field error;
    struct snmp_field error_index;
    struct snmp_field varbind_list;
    struct snmp_field service_varbind;
    struct snmp_field param1_varbind;
    //struct snmp_field param2_varbind; change
    
    
    size_t req_length = 0;
    size_t header_len = 0;
    size_t offset = 0;   
    
    encode_varbind(&service_varbind, service, service_len, NULL, ASN_NULL, 0);

    encode_varbind(&param1_varbind, param1, param1_len, (u_char*)&value1, ASN_INTEGER, sizeof(int));

    //encode_varbind(&param2_varbind, param2, param2_len, (u_char*)&value2, ASN_INTEGER, sizeof(int)); change   
    
    // u_char param1_val[50];
    // u_char param2_val[10];
    // size_t p1_val_len, p2_val_len;
    
    // p1_val_len = decode_varbind(&param1_varbind, param1_val);
    // printf("param_val %s \n", param1_val);
    // printf("p1_val_len %d \n", p1_val_len);
    // param1_val[p1_val_len] = '\0';

    // printf("param_val %s \n", param1_val);



    // p2_val_len = decode_varbind(&param2_varbind, param2_val);
    // printf("p2_val_len %d \n", p2_val_len);

    // u_int32_t n_int_val;
    // int param_int;
    // memcpy(&n_int_val, param2_val, p2_val_len);
    // param_int = ntohl(n_int_val);

    // printf("param_int: %d \n", param_int);

    //req_length += service_varbind.length + 2 + param1_varbind.length + 2 + param2_varbind.length + 2; change
    req_length += service_varbind.length + 2 + param1_varbind.length + 2;

    varbind_list.type = ASN_OPAQUE_TAG2; // sequence
    varbind_list.length = req_length;

    offset = service_varbind.length+2;
    
    memcpy(varbind_list.value, &service_varbind, service_varbind.length+2);

    
    memcpy((varbind_list.value + offset), &param1_varbind, param1_varbind.length+2);
    // offset += param1_varbind.length+2;

    // memcpy((varbind_list.value + offset), &param2_varbind, param2_varbind.length+2); change

    offset = 0;
    req_length += 2;
    
    error_index.type = ASN_INTEGER;
    error_index.length = 1;
    u_char e_val = 0;    
    strncpy(error_index.value, &e_val, 1);

    req_length += error_index.length +2;

    
    error.type = ASN_INTEGER;
    error.length = 1;    
    strncpy(error.value, &e_val, 1);

    req_length += error.length +2;

    request_id.type = ASN_INTEGER;
    request_id.length = sizeof(u_int16_t);
    u_int16_t req_val = htons(rand());
    // printf("request is %d \n", ntohs(req_val));
    strncpy(request_id.value, (u_char*)&req_val, sizeof(u_int16_t));

    req_length += request_id.length+2;
    request.type = SNMP_MSG_GET;
    request.length = req_length;    
    
    offset += request_id.length+2;    
    memcpy(request.value, &request_id,request_id.length+2);    
    memcpy(request.value+offset, &error,error.length+2);    
    offset += error.length+ 2;   
    memcpy(request.value+offset, &error_index,error_index.length+2);
    offset += error_index.length+ 2;    
    memcpy(request.value+offset, &varbind_list,varbind_list.length+2);

    req_length += 2;
    
    community.type = ASN_OCTET_STR;
    community.length = (u_char)strlen("public");
    strncpy(community.value, "public", strlen("public")+1);    
    header_len += community.length+2;
  
    version.type = ASN_INTEGER;
    version.length = 1;    
    u_char v_value = SNMP_VERSION_2c;
    strncpy(version.value, &v_value, 1);

    header_len += version.length+2;
    
    snmp_message.type = ASN_OPAQUE_TAG2; 
    snmp_message.length = req_length+header_len;
    memset(snmp_message.value, 0x00, snmp_message.length);

    memcpy(snmp_message.value, &version, sizeof(version));
    memcpy((snmp_message.value +version.length+2), &community, community.length+2);   
    
    memcpy((snmp_message.value + header_len), &request, req_length+2);
    *message_len = snmp_message.length+2;
    memcpy(message, &snmp_message, snmp_message.length+2);
    
}

// encode a get request with 2 int parameters
void encode_get_request_with_param_int_int(u_char* message, size_t* message_len, oid* service, size_t service_len, oid* param1, size_t param1_len, int value1, size_t fn_len, oid* param2, size_t param2_len, int value2){
    struct snmp_field snmp_message;
    struct snmp_field version;
    struct snmp_field community;
    struct snmp_field request;
    struct snmp_field request_id;
    struct snmp_field error;
    struct snmp_field error_index;
    struct snmp_field varbind_list;
    struct snmp_field service_varbind;
    struct snmp_field param1_varbind;
    struct snmp_field param2_varbind;
    
    
    size_t req_length = 0;
    size_t header_len = 0;
    size_t offset = 0;   
    
    encode_varbind(&service_varbind, service, service_len, NULL, ASN_NULL, 0);

    encode_varbind(&param1_varbind, param1, param1_len, (u_char*)&value1, ASN_INTEGER, fn_len);

    encode_varbind(&param2_varbind, param2, param2_len, (u_char*)&value2, ASN_INTEGER, sizeof(int));    
    
    // u_char param1_val[50];
    // u_char param2_val[10];
    // size_t p1_val_len, p2_val_len;
    
    // p1_val_len = decode_varbind(&param1_varbind, param1_val);
    // printf("param_val %s \n", param1_val);
    // printf("p1_val_len %d \n", p1_val_len);
    // param1_val[p1_val_len] = '\0';

    // printf("param_val %s \n", param1_val);



    // p2_val_len = decode_varbind(&param2_varbind, param2_val);
    // printf("p2_val_len %d \n", p2_val_len);

    // u_int32_t n_int_val;
    // int param_int;
    // memcpy(&n_int_val, param2_val, p2_val_len);
    // param_int = ntohl(n_int_val);

    // printf("param_int: %d \n", param_int);

    req_length += service_varbind.length + 2 + param1_varbind.length + 2 + param2_varbind.length + 2;

    varbind_list.type = ASN_OPAQUE_TAG2; // sequence
    varbind_list.length = req_length;

    offset = service_varbind.length+2;
    
    memcpy(varbind_list.value, &service_varbind, service_varbind.length+2);

    
    memcpy((varbind_list.value + offset), &param1_varbind, param1_varbind.length+2);
    offset += param1_varbind.length+2;

    memcpy((varbind_list.value + offset), &param2_varbind, param2_varbind.length+2);

    offset = 0;
    req_length += 2;
    
    error_index.type = ASN_INTEGER;
    error_index.length = 1;
    u_char e_val = 0;    
    strncpy(error_index.value, &e_val, 1);

    req_length += error_index.length +2;

    
    error.type = ASN_INTEGER;
    error.length = 1;    
    strncpy(error.value, &e_val, 1);

    req_length += error.length +2;

    request_id.type = ASN_INTEGER;
    request_id.length = sizeof(u_int16_t);
    u_int16_t req_val = htons(rand());
    // printf("request is %d \n", ntohs(req_val));
    strncpy(request_id.value, (u_char*)&req_val, sizeof(u_int16_t));

    req_length += request_id.length+2;
    request.type = SNMP_MSG_GET;
    request.length = req_length;    
    
    offset += request_id.length+2;    
    memcpy(request.value, &request_id,request_id.length+2);    
    memcpy(request.value+offset, &error,error.length+2);    
    offset += error.length+ 2;   
    memcpy(request.value+offset, &error_index,error_index.length+2);
    offset += error_index.length+ 2;    
    memcpy(request.value+offset, &varbind_list,varbind_list.length+2);

    req_length += 2;
    
    community.type = ASN_OCTET_STR;
    community.length = (u_char)strlen("public");
    strncpy(community.value, "public", strlen("public")+1);    
    header_len += community.length+2;
  
    version.type = ASN_INTEGER;
    version.length = 1;    
    u_char v_value = SNMP_VERSION_2c;
    strncpy(version.value, &v_value, 1);

    header_len += version.length+2;
    
    snmp_message.type = ASN_OPAQUE_TAG2; 
    snmp_message.length = req_length+header_len;
    memset(snmp_message.value, 0x00, snmp_message.length);

    memcpy(snmp_message.value, &version, sizeof(version));
    memcpy((snmp_message.value +version.length+2), &community, community.length+2);   
    
    memcpy((snmp_message.value + header_len), &request, req_length+2);
    *message_len = snmp_message.length+2;
    memcpy(message, &snmp_message, snmp_message.length+2);
    
}

// decodes the response received from the kernel and retrieves the value
// need to get each field to get its length
void decode_get_response(struct snmp_field *recv_message, pid_t *ret_pid) {
    struct snmp_field *recv_community;
    struct snmp_field *recv_request;
    struct snmp_field *error;
    struct snmp_field *recv_varbind_list;
    struct snmp_field *recv_varbind;
    struct snmp_field *recv_object_id;
    struct snmp_field *recv_object_value;
    size_t offset = 3; //version field
    u_int32_t ret_value;
    u_char error_value;
    
    recv_community = (struct snmp_field*) (recv_message->value+offset);
    offset += recv_community->length+2;
    
    recv_request = (struct snmp_field*) (recv_message->value+offset);
    offset += 2; // request type and length data members
    offset += 4; // request id
    error = (struct snmp_field*) (recv_message->value+offset);
    memcpy(&error_value, error->value, 1);
    if (error_value == 2) {
    	printf("invalid oid\n");
	exit(1);
    }

    offset += 3 + 3; 
    recv_varbind_list = (struct snmp_field*) (recv_message->value+offset);    
    offset += 2;

    recv_varbind = (struct snmp_field*) (recv_message->value+offset);    
    offset += 2;

    recv_object_id = (struct snmp_field*) (recv_message->value+offset);
    offset +=  recv_object_id->length + 2;

    // and finally the value
    recv_object_value = (struct snmp_field*) (recv_message->value+offset);
    
    memcpy(&ret_value, (pid_t*)(recv_object_value->value), sizeof(pid_t));
    *ret_pid = ntohl(ret_value);
    
}

void decode_get_response_long(struct snmp_field *recv_message, long *ret_long) {
    struct snmp_field *recv_community;
    struct snmp_field *recv_request;
    struct snmp_field *error;
    struct snmp_field *recv_varbind_list;
    struct snmp_field *recv_varbind;
    struct snmp_field *recv_object_id;
    struct snmp_field *recv_object_value;
    size_t offset = 3; //version field
    u_int32_t ret_value;
    u_char error_value;
    
    recv_community = (struct snmp_field*) (recv_message->value+offset);
    offset += recv_community->length+2;
    
    recv_request = (struct snmp_field*) (recv_message->value+offset);
    offset += 2; // request type and length data members
    offset += 4; // request id
    error = (struct snmp_field*) (recv_message->value+offset);
    memcpy(&error_value, error->value, 1);
    if (error_value == 2) {
        printf("invalid oid\n");
    exit(1);
    }

    offset += 3 + 3; 
    recv_varbind_list = (struct snmp_field*) (recv_message->value+offset);    
    offset += 2;

    recv_varbind = (struct snmp_field*) (recv_message->value+offset);    
    offset += 2;

    recv_object_id = (struct snmp_field*) (recv_message->value+offset);
    offset +=  recv_object_id->length + 2;

    // and finally the value
    recv_object_value = (struct snmp_field*) (recv_message->value+offset);
    
    memcpy(&ret_value, (long*)(recv_object_value->value), sizeof(long));
    *ret_long = ntohl(ret_value);
    
}

void construct_get_response(struct snmp_field *recv_message) {
	struct snmp_field *recv_community;
    struct snmp_field *recv_request;
    struct snmp_field *recv_varbind_list;
    struct snmp_field *recv_varbind;
    struct snmp_field *recv_object_id;
    struct snmp_field *recv_object_value;
    size_t offset = 0;
    
    printf("rcv_message: length: %d \n", recv_message->length);
    offset = 3; //version field
    recv_community = (struct snmp_field*) (recv_message->value+offset);
    printf("rcv_message: community type: %d \n", recv_community->type);
    printf("rcv_message: community length: %d \n", recv_community->length);
    offset += recv_community->length+2;
    recv_request = (struct snmp_field*) (recv_message->value+offset);
    printf("rcv_message: recv_request length: %d \n", recv_request->length);
    recv_request->type = SNMP_MSG_RESPONSE;
    offset += 2;
    // update the value and update all the lengths
    //increasing the length of the Value field also increases the length of the Varbind, Varbind List, PDU, and SNMP message fields
    offset += 4 + 3 + 3; // request id is an integer of 4 bytes plus type and length, error and error index are 3 bytes each
    recv_varbind_list = (struct snmp_field*) (recv_message->value+offset);
    printf("rcv_message: recv_varbind_list length: %d \n", recv_varbind_list->length);
    offset += 2;
    recv_varbind = (struct snmp_field*) (recv_message->value+offset);
    printf("rcv_message: recv_varbind length: %d \n", recv_varbind->length);
    offset += 2;

    recv_object_id = (struct snmp_field*) (recv_message->value+offset);
    
    offset +=  recv_object_id->length + 2;

    // and finally the value
    recv_object_value = (struct snmp_field*) (recv_message->value+offset);
    
    struct snmp_field new_object_value;
    new_object_value.type = ASN_INTEGER;    
    new_object_value.length = sizeof(pid_t);
    unsigned int pid_value = getpid();
    // memset(recv_object_value->value, 0x00, sizeof(long));
    memcpy(new_object_value.value, (u_char*)&pid_value, sizeof(pid_t));    
    memcpy(recv_object_value, &new_object_value, new_object_value.length+2);

    printf("pid: %d \n", pid_value);

    // for testing
    // unsigned int pid_from_request;
    // memcpy(&pid_from_request, (pid_t*)recv_object_value->value, sizeof(pid_t));
	// printf("pid_from_request: %d\n", pid_from_request);

    recv_varbind->length += sizeof(pid_t);
    recv_varbind_list->length += sizeof(pid_t);
    recv_request->length += sizeof(pid_t);
    recv_message->length += sizeof(pid_t);
}
