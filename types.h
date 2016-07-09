typedef u_long oid;

struct counter64 {
  u_long          high;
  u_long          low;
};

#define MAX_OID_LEN	    128 /* max subid's in an oid */

typedef union {
   long           *integer;
   u_char         *string;
   oid            *objid;
   u_char         *bitstring;
   struct counter64 *counter64;
   float          *floatVal;
   double         *doubleVal;

} netsnmp_vardata;

typedef struct variable_list {
   /** NULL for last variable */
   struct variable_list *next_variable;    
   /** Object identifier of variable */
   oid            *name;   
   /** number of subid's in name */
   size_t          name_length;    
   /** ASN type of variable */
   u_char          type;   
   /** value of variable */
    netsnmp_vardata val;
   /** the length of the value to be copied into buf */
   size_t          val_len;
   /** buffer to hold the OID */
   oid             name_loc[MAX_OID_LEN];  
   /** 90 percentile < 40. */
   u_char          buf[40];
   /** (Opaque) hook for additional data */
   void           *data;
   /** callback to free above */
   void            (*dataFreeHook)(void *);    
   int             index;
} netsnmp_variable_list;


typedef struct snmp_pdu {

#define non_repeaters	errstat
#define max_repetitions errindex

    /*
     * Protocol-version independent fields
     */
    /** snmp version */
    long            version;
    /** Type of this PDU */	
    int             command;
    /** Request id - note: not incremented on retries */
    long            reqid;  
    /** Message id for V3 messages note: incremented for each retry */
    long            msgid;
    /** Unique ID for incoming transactions */
    long            transid;
    /** Session id for AgentX messages */
    long            sessid;
    /** Error status (non_repeaters in GetBulk) */
    long            errstat;
    /** Error index (max_repetitions in GetBulk) */
    long            errindex;       
    /** Uptime */
    u_long          time;   
    u_long          flags;

    int             securityModel;
    /** noAuthNoPriv, authNoPriv, authPriv */
    int             securityLevel;  
    int             msgParseModel;

    /**
     * Transport-specific opaque data.  This replaces the IP-centric address
     * field.  
     */
    
    void           *transport_data;
    int             transport_data_length;

    /**
     * The actual transport domain.  This SHOULD NOT BE FREE()D.  
     */

    const oid      *tDomain;
    size_t          tDomainLen;

    netsnmp_variable_list *variables;


    /*
     * SNMPv1 & SNMPv2c fields
     */
    /** community for outgoing requests. */
    u_char         *community;
    /** length of community name. */
    size_t          community_len;  

    /*
     * Trap information
     */
    /** System OID */
    oid            *enterprise;     
    size_t          enterprise_length;
    /** trap type */
    long            trap_type;
    /** specific type */
    long            specific_type;
    /** This is ONLY used for v1 TRAPs  */
    unsigned char   agent_addr[4];  

    /*
     *  SNMPv3 fields
     */
    /** context snmpEngineID */
    u_char         *contextEngineID;
    /** Length of contextEngineID */
    size_t          contextEngineIDLen;     
    /** authoritative contextName */
    char           *contextName;
    /** Length of contextName */
    size_t          contextNameLen;
    /** authoritative snmpEngineID for security */
    u_char         *securityEngineID;
    /** Length of securityEngineID */
    size_t          securityEngineIDLen;    
    /** on behalf of this principal */
    char           *securityName;
    /** Length of securityName. */
    size_t          securityNameLen;        
    
    /*
     * AgentX fields
     *      (also uses SNMPv1 community field)
     */
    int             priority;
    int             range_subid;
    
    void           *securityStateRef;
} netsnmp_pdu;
