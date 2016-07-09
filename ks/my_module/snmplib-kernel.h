#include "types.h"

void decode_oid(unsigned char* en_oid, size_t en_oid_len, oid* dec_oid, size_t *dec_oid_len) {
	
	int i, dec_oid_index;

	// first byte represents .1.3
	if (en_oid[0] == 43){
		dec_oid[0] = 1;
		dec_oid[1] = 3;
	}

	dec_oid_index = 2;

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

int decode_varbind(struct snmp_field *vb, u_char *param_val) {
    struct snmp_field *vb_oid;
    struct snmp_field *vb_val;   

    vb_oid = (struct snmp_field *) (vb->value);

    vb_val = (struct snmp_field *) (vb->value + vb_oid->length + 2);    
    
    memcpy(param_val, vb_val->value, vb_val->length);

    return vb_val->length;    
    
}

void construct_get_response(struct snmp_field *recv_message, pid_t *pid_value) {
    struct snmp_field *recv_community;
    struct snmp_field *recv_request;
    struct snmp_field *recv_varbind_list;
    struct snmp_field *recv_varbind;
    struct snmp_field *recv_object_id;
    struct snmp_field *recv_object_value;
    size_t offset = 0;
    struct snmp_field new_object_value;
    
    offset = 3; //version field
    recv_community = (struct snmp_field*) (recv_message->value+offset);
    offset += recv_community->length+2;
    
    recv_request = (struct snmp_field*) (recv_message->value+offset);
    recv_request->type = SNMP_MSG_RESPONSE;
    offset += 2;
    
    // update the value and update all the lengths
    //increasing the length of the Value field also increases the length of the Varbind, Varbind List, PDU, and SNMP message fields
    offset += 6 + 3 + 3; // request id is an integer of 4 bytes plus type and length, error and error index are 3 bytes each
    
    recv_varbind_list = (struct snmp_field*) (recv_message->value+offset);
    offset += 2;
    
    recv_varbind = (struct snmp_field*) (recv_message->value+offset);
    offset += 2;

    recv_object_id = (struct snmp_field*) (recv_message->value+offset);
    offset +=  recv_object_id->length + 2;

    // and finally the value
    recv_object_value = (struct snmp_field*) (recv_message->value+offset);
    
    
    new_object_value.type = ASN_INTEGER;    
    new_object_value.length = sizeof(pid_t);
   
    memcpy(new_object_value.value, (u_char*)pid_value, sizeof(pid_t));
    
    memcpy(recv_object_value, &new_object_value, new_object_value.length+2);

    //printk("pid: %d \n", pid_value);  

    recv_varbind->length += sizeof(pid_t);
    recv_varbind_list->length += sizeof(pid_t);
    recv_request->length += sizeof(pid_t);
    recv_message->length += sizeof(pid_t);
}
