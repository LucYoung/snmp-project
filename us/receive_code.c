    unsigned char recv_buff[1500];
    int nread;
    unsigned char recv_snmp[50];
    long retval;
    
    while(!received) {
      nread = read(tun_fd, recv_buff, 1500);
      if (nread < 0) {
	perror("error reading from device");
	close(tun_fd);
	exit(1);
      } else {
	printf("read %d bytes \n", nread);
	received = 1;
      }
    } 
    
    memcpy(recv_snmp, (recv_buff+sizeof(struct iphdr) + sizeof(struct udphdr)), sizeof(recv_snmp));
    printf("received snmp type %d \n", recv_snmp[13]);
    printf("received snmp value type %d \n", recv_snmp[42]);
    printf("received snmp value length %d \n", recv_snmp[43]);
    
    memcpy((unsigned char*) &retval, (recv_snmp+43), 4 );
    printf("received snmp ret value %d \n", retval);