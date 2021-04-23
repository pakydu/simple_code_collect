/*
*   This file trys to collect some network APIs
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string>


//- Define the max length of formatted ip address
#define IP_ADDRESS_MAX_LENGTH (16)
#define gettid() syscall(__NR_getpid)



/*
* This func will return a interface's network setting infomation
* You can refer to the below file content.
*/
/* # cat /etc/network/interfaces
// auto lo
// iface lo inet loopback

// auto eth0
// iface eth0 inet static
// address 10.161.93.185
// netmask 255.255.0.0
// gateway 10.161.92.1

// auto eth1
// iface eth1 inet static
// address 192.168.1.250
// netmask 255.255.255.0
*/
const char* IP_CONFIG_FILE = "/etc/network/interfaces";
int get_ipConfig_by_systemfile(const char *if_name, int *dhcp, unsigned int *ip_addr, unsigned int *net_mask, unsigned int *gw)
{
	int ret = -1;
	int stage = 0;
	char line_buf[256];
	char if_cfg[32];
	char *tmp = NULL;

	*dhcp = 0;
	*ip_addr = 0;
	*net_mask = 0;
	*gw = 0;

//C++ code
	sprintf(if_cfg, "iface %s inet ", if_name);
	std::ifstream fin(IP_CONFIG_FILE);
	std::string line;
	if (fin.is_open())
	{
		while (getline (fin, line))
		{
			std::size_t found = line.find_first_of("\r");//try to handle Window file format.
			if (found != std::string::npos)
				line.erase (found);

			if (stage == 0)
			{
				found = line.find(if_cfg);
				if(found!=std::string::npos)
				{
					stage = 1;
					std::string tmpStr = line.substr(strlen(if_cfg));
					if (tmpStr.compare("dhcp") == 0)
					{
						dhcp = 1;
					}
					else if (tmpStr.compare("static") == 0)
					{
						dhcp = 0;
					}
					else
					{
						ret = 2;
						goto error;
					}
				}
			}
			else if (stage == 1)
			{
				if (line.length() < 3)
				{
					break;
				}

				std::string tmpStr = line;
				tmpStr = tmpStr.substr(tmpStr.find_first_not_of(' '), tmpStr.find_last_not_of(' ') + 1);
				if (tmpStr.at(0) == '#')//skip the comment line.
					continue;	

				struct in_addr sin_addr;
				if (tmpStr.find("address ") != std::string::npos)
				{
					tmpStr = tmpStr.substr(strlen("address "));
					if (inet_pton(AF_INET, tmpStr.c_str(), &sin_addr) == 1)
					{
						*ip_addr = sin_addr.s_addr;
					}
				}
				else if (tmpStr.find("netmask ") != std::string::npos)
				{
					tmpStr = tmpStr.substr(strlen("netmask "));
					if (inet_pton(AF_INET, tmpStr.c_str(), &sin_addr) == 1)
					{
						*net_mask = sin_addr.s_addr;
					}
				}
				else if (tmpStr.find("gateway ") != std::string::npos)
				{	
					tmpStr = tmpStr.substr(strlen("gateway "));
					if (inet_pton(AF_INET, tmpStr.c_str(), &sin_addr) == 1)
					{
						*gw = sin_addr.s_addr;
					}
				}

				if (ip_addr != 0
				 && net_mask != 0
				 && gw != 0)
				{
					stage = 2;
					break;
				}
			}
		}
		
		if ( (*dhcp == 1)
		  || (*dhcp == 0 && *ip_addr != 0 && *net_mask != 0 && *gw != 0)
		)
		{
			stage = 2;
		}

		if((strcmp(if_name,ethInterfaces[ETH1_SUB_INDEX])==0)&&(*dhcp == 0 && *ip_addr != 0 && *net_mask != 0))
		{
			stage = 2;
		}

		if (2 == stage)
		{
			ret = 0;
		}
		
	}

error:
	if (fin.is_open())
	{
		fin.close()
	}

	return ret;
}

int set_ipConfig_by_systemfile(const char *if_name, int dhcp, unsigned int ip_addr, unsigned int net_mask, unsigned int gw)
{
	int ret = 0;
	int stage = 0;
	char line_buf[256] = {0};
	std::string strNewBuf;
	char if_cfg[32] = {0};
	char if_auto[32] = {0};
	bool bAppendAuto = true;
	const char *if_val = "static";
	
	char ip_cfg[256] = {0};
	char ip[MAX_IPADDR_LEN] = {0};
	char netmask[MAX_IPADDR_LEN] ={0};
	char gateway[MAX_IPADDR_LEN] = {0};
	struct in_addr iaddr = {0};

	FILE *fp = fopen(IP_CONFIG_FILE, "r+");
	if (fp != NULL)
	{
		fseek(fp, 0, SEEK_SET);
		sprintf(if_cfg, "iface %s inet ", if_name);
		sprintf(if_auto, "auto %s", if_name);
		if (0 != dhcp)
		{
			if_val = "dhcp";
		}
		
		iaddr.s_addr = ip_addr;
		strcpy(ip, inet_ntoa(iaddr));

		iaddr.s_addr = net_mask;
		strcpy(netmask, inet_ntoa(iaddr));

		iaddr.s_addr = (gw);
		strcpy(gateway, inet_ntoa(iaddr));

		if ((strchr(if_name, ':'))||(strcmp(gateway,"0.0.0.0")==0))
		{
			//the sub IP make the gateway invalid
			sprintf(ip_cfg, "address %s\nnetmask %s\n#gateway %s", ip, netmask, gateway);
		}
		else
		{
			sprintf(ip_cfg, "address %s\nnetmask %s\ngateway %s", ip, netmask, gateway);
		}

		//stage: 0: need to find if config
		//		1: need to write ip
		//		2: have been write
		while (fgets(line_buf,256,fp) != NULL)
		{
			if ('#' == *line_buf)
			{
				continue;
			}

			if (strstr(line_buf, if_auto) != NULL)
			{
				bAppendAuto = false;
			}
				
			if (stage == 0)
			{
				char *tmp = NULL;
				tmp = strstr(line_buf, if_cfg);
				if (NULL != tmp)
				{
					//if dhcp enable no need to set the ip
					if (dhcp)
					{
						stage = 2;
					}
					else
					{
						stage = 1;
					}
					strNewBuf.append(if_cfg);
					strNewBuf.append(if_val);
					strNewBuf.append("\n");
				}
				else
				{
					strNewBuf.append(line_buf);
				}

			}
			else if (stage == 1)
			{
				if (strlen(line_buf) < 3)
				{
					stage = 2;
					strNewBuf.append(ip_cfg);
					strNewBuf.append("\n\n");
				}
				else
				{
					// the line is the config of interface do nothing
				}
			}
			else
			{
				strNewBuf.append(line_buf);
				continue;
			}
		}

		//stage 0: need to write all the configuration
		//stage 1: need to write ip
		//stage 2: successful
		if (stage == 0)
		{
			//auto ethx
			bAppendAuto = false;
			strNewBuf.append(if_auto);
			strNewBuf.append("\n");

			//iface ethx inet static
			strNewBuf.append(if_cfg);
			strNewBuf.append(if_val);
			strNewBuf.append("\n");

			if (0 == dhcp)
			{
				strNewBuf.append(ip_cfg);
				strNewBuf.append("\n");
			}

			strNewBuf.append("\n");
		}
		else if (stage == 1)
		{
			strNewBuf.append(ip_cfg);
			strNewBuf.append("\n\n");
		}
		
		//make sure whether we shoudl append the "auto ethx"
		if (bAppendAuto)//we will insert the auto for the interface.
		{
			std::size_t found = strNewBuf.find(if_cfg);
			if (found!=std::string::npos)
			{
				std::string tmpInser = if_auto;
				tmpInser.append("\n");
				strNewBuf.insert(found,tmpInser);
			}
		}

		fclose(fp);

		if (strNewBuf.length() > 0)
		{
	
			fp = fopen(IP_CONFIG_FILE, "w+");
			if (fp != NULL)
			{
				fseek(fp, 0, SEEK_SET);
				fputs(strNewBuf.c_str(), fp);

				ret = 0;
				fclose(fp);
				fp = NULL;
			}
			else
			{
				ret = 1;
			}
		}
	}
	else
	{
		ret = 1;
	}

	return ret;
}



int get_mac_address(const char *eth_name, unsigned char  mac[6], char *fmt_buf)
{
	if (NULL == eth_name)
		return -1;

	int ret = -1,  sock_fd = -1;
	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
		return ret;

	struct ifreq if_hwaddr;	
	safe_strncpy(if_hwaddr.ifr_name, eth_name, IFNAMSIZ);
	if (ioctl(sock_fd, SIOCGIFHWADDR, &if_hwaddr) != -1) {
		memcpy(mac, (unsigned char *) if_hwaddr.ifr_hwaddr.sa_data, 6);
		if (fmt_buf) {
			sprintf(fmt_buf, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
					if_hwaddr.ifr_addr.sa_data[0], if_hwaddr.ifr_addr.sa_data[1], 
					if_hwaddr.ifr_addr.sa_data[2], if_hwaddr.ifr_addr.sa_data[3],
					if_hwaddr.ifr_addr.sa_data[4], if_hwaddr.ifr_addr.sa_data[5] );
		}			
		ret = 0;
	}	
	shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
	
	return ret;
}


int get_ip_address(const char *eth_name, char *ip_buf)
{
	if ((NULL == eth_name) || (NULL == ip_buf))
		return -1;

	int ret = -1, sock_fd = -1;
	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
		return ret;

	struct ifreq if_r;
	safe_strncpy(if_r.ifr_name, eth_name, IFNAMSIZ);
	if_r.ifr_addr.sa_family = AF_INET;
	
	if (ioctl(sock_fd, SIOCGIFADDR, &if_r) != -1 ){
		safe_strncpy(ip_buf, inet_ntoa(((struct sockaddr_in *)&if_r.ifr_addr)->sin_addr), IP_ADDRESS_MAX_LENGTH);
		ip_buf[IP_ADDRESS_MAX_LENGTH - 1] = 0;
		ret = 0;
	}
	shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
	
	return ret;
}


int get_broadcast_address(const char *eth_name, char *bcast_buf)   
{
	int ret = -1;
	if (NULL == bcast_buf || NULL == eth_name)
		return ret;

	int sock_fd = INVALID_FD;
	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == INVALID_FD)
		return ret;

	struct ifreq if_r;
	safe_strncpy(if_r.ifr_name, eth_name, IFNAMSIZ);
	if_r.ifr_addr.sa_family = AF_INET;

	if (ioctl(sock_fd, SIOCGIFBRDADDR, &if_r) != -1 ){
		safe_strncpy(bcast_buf, inet_ntoa(((struct sockaddr_in *)&if_r.ifr_addr)->sin_addr), IP_ADDRESS_MAX_LENGTH);
		bcast_buf[IP_ADDRESS_MAX_LENGTH - 1] = 0;
		ret = 0;
	}

	shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
	
	return ret;	
}



int get_subnet_mask(const char *eth_name, char *mask_buf)
{
	if ((NULL == eth_name) || (NULL == mask_buf))
		return -1;

	int ret = -1, sock_fd = -1;
	if ((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
		return ret;

	struct ifreq if_r;
	safe_strncpy(if_r.ifr_name, eth_name, IFNAMSIZ);
	if_r.ifr_addr.sa_family = AF_INET;
	
	if (ioctl(sock_fd, SIOCGIFNETMASK, &if_r) != -1 ){
		safe_strncpy(mask_buf, inet_ntoa(((struct sockaddr_in *)&if_r.ifr_addr)->sin_addr), IP_ADDRESS_MAX_LENGTH);
		mask_buf[IP_ADDRESS_MAX_LENGTH - 1] = 0;
		ret = 0;
	}
	shutdown(sock_fd, SHUT_RDWR);
	close(sock_fd);
	
	return ret;

}


int get_gateway(const char *eth_name, char *gw_buf)   
{
	int ret = -1;
	if ((NULL == eth_name) || (NULL == gw_buf))
		return ret;

	FILE *fp = fopen("/proc/net/route", JV_READ);
	if(NULL == fp)
		return ret;

	char ethface[16] = {0}, buf[256] = {0};
	unsigned long dest_addr = 0, gate_addr = 0;

	/* Skip title line */
	fgets(buf, sizeof(buf), fp);
	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%s\t%lx\t%lx", ethface, &dest_addr, &gate_addr) != 3 || dest_addr != 0)
			continue;
		if (strncmp(ethface, eth_name, strlen(eth_name)) == 0) {
			struct in_addr gate_way;
			gate_way.s_addr = gate_addr;
			safe_strncpy(gw_buf, inet_ntoa(gate_way), IP_ADDRESS_MAX_LENGTH);
			gw_buf[IP_ADDRESS_MAX_LENGTH - 1] = 0;
			ret = 0;
			break;
		}
	}
	fclose(fp);

	return ret;   
}   


int get_system_DNS(int count, unsigned int dns[])
{
	if (NULL == dns || count <= 0)
		return 0;

	FILE *fp = fopen("/etc/resolv.conf", "r+");
	if (NULL == fp)
		return 0;

	int num = 0;
	char buf[256] = {0};
	char str[16] = {0};
	while ((fgets(buf, sizeof(buf), fp) != NULL) && (count > 0)){
		char dns_str[16] = {0};
		if (sscanf(buf, "%s\t%s", str, dns_str) != 2)
			continue;
		if(strcmp(str, "nameserver") == 0){
			dns[num++] = inet_addr(dns_str);
			count--;
			bzero(str, sizeof(str));
		}
	}

	fclose(fp);
	return num;
}


int get_ip_mode(const char *eth_name)//dhcp or static
{
	int type = -1;
	if (NULL == eth_name)
		return type;

	FILE *fp = fopen("/etc/network/interfaces", "r+");
	if (NULL == fp)
		return type;

	char buf[256] = {0};
	while (fgets(buf, 256, fp) != NULL) {
		char str[16] = {0}, ethernet_name[16] = {0}, str1[16] = {0};
		char ip_type[16] = {0};
		if (sscanf(buf, "%s\t%s\t%s\t%s", str, ethernet_name, str1, ip_type) != 4)
			continue;
		if ((strcmp(eth_name, ethernet_name) == 0) && (strcmp(str, "iface") == 0)
			 && (strcmp(str1, "inet") == 0)){
			if(strcmp(ip_type, "static") == 0)
				type = 0;
			else if(strcmp(ip_type, "dhcp") == 0)
				type = 1;
			break;
		}
	}

	fclose(fp);
	return type;
}


static int create_hostname_foramt(const char *hostname, unsigned char *hostname_format)
{
	int skip_len = 0 ;
	char tmp_hostname[MAX_PACK_LEN] = {0};
	unsigned char *tmp_hostname_format = hostname_format;
	
	if (hostname_format == NULL)
		return 0;
		
	safe_strncpy(tmp_hostname, hostname, strlen(hostname) + 1);

	strcat((char*)tmp_hostname,".");
	int tmp_length = (int)strlen((char*)tmp_hostname);
	
	for (int i = 0; i < tmp_length; i++) {
		if (tmp_hostname[i] == '.') {
			*hostname_format++ = i - skip_len;
			for ( ; skip_len < i; skip_len++)
				*hostname_format++=tmp_hostname[skip_len];
			skip_len++; //or skip_len=i+1;
		}
	}
	
    *hostname_format++ = '\0';

    return strlen((char*)tmp_hostname_format) + 1;//include the '\0'
}


static int create_dns_query_head(dns_head_t *dns_head)
{
	dns_head->id = (unsigned short)htons(getpid());
	dns_head->qr = 0;      //This is a query
	dns_head->opcode = 0;  //This is a standard query
	dns_head->aa = 0;      //Not Authoritative
	dns_head->tc = 0;      //This message is not truncated
	dns_head->rd = 1;      //Recursion Desired
	dns_head->ra = 0;      //Recursion not available! hey we dont have it (lol)
	dns_head->z  = 0;
	dns_head->ad = 0;
	dns_head->cd = 0;
	dns_head->rcode = 0;
	dns_head->q_count = htons(1);   //we have only 1 question
	dns_head->ans_count  = 0;
	dns_head->auth_count = 0;
	dns_head->add_count  = 0;

    return sizeof(dns_head_t);
}


static unsigned char* get_query_hostname(unsigned char *reader, unsigned char *buffer, int *count)
{
	unsigned int p = 0;
	unsigned int find_offset = 0;
	unsigned int offset;

	unsigned char *name = (unsigned char*)calloc(256, sizeof(unsigned char));
	*count = 1;
	
	//names format: 3www6google3com
	while (*reader != 0) {
		//- do the comparation
		if (*reader >= 192 && find_offset == 0) {
			offset = ((*reader)*256 + *(reader+1))&(0x3fff); //0x3fff: offset
			reader = buffer + offset - 1;
			find_offset = 1;
		} else
			name[p++] = *reader;

		reader++;
		
		if (find_offset == 0)
			*count = *count + 1;
	}
	
	if (find_offset == 1)
		*count = *count + 1;  //number of steps we actually moved forward in the packet
	
	uint32_t i = 0;
	for (; i < strlen((const char*)name); i++) {
		p = name[i];
		for (int j = 0; j < (int)p; j++) {
			name[i] = name[i+1];
			i = i + 1;
		}
		name[i]='.';
	}
	//- remove the last dot
	name[i-1]='\0';

	return name;		
}


int get_hostbyname(const char *hostname, struct timeval timeout, dns_answer_t *resp_infor)
{
	int ret = 1;
	dns_head_t *head;
	unsigned char upd_send_buf[MAX_PACK_LEN] = {0};
	unsigned char upd_recv_buf[MAX_PACK_LEN] = {0};

#if SUPPORT_DNS_CACHE_RECORD
	struct dns_entry *conf_data;
	const char *DnsCacheFile = DNS_CACHE_RECORD_FILE;
	conf_data = parse_DnsCache_file(DnsCacheFile);
#endif
	if (hostname == NULL || resp_infor == NULL)
		return ret;
	else
		memset((void *)resp_infor, 0, sizeof(resp_infor));

	struct sockaddr_in addr;
	if(inet_aton(hostname, &addr.sin_addr))/*if the domain format is a xxx.xxx.xxx.xxx foramt, maybe not need  doing "query" */
	{
		resp_infor->type = 1;
		resp_infor->tclass = 1;/* IPv4 only */
		safe_strncpy((resp_infor->strIp), hostname, sizeof(resp_infor->strIp));
		syslog(LOG_USER | LOG_DEBUG, "LG4_get_hostbyname for the host: %s", hostname);
		return 0;
	}

	fd_set inset;
	dns_res_record_t answers[20];
	/* get system dns server IP list. */
	unsigned int dns_servers[MAX_DNS_COUNT] = {0};
	LG4_get_DNS(MAX_DNS_COUNT, dns_servers);
	if (MAX_DNS_COUNT >= 2 && dns_servers[0] == 0 && dns_servers[1] == 0)
		return -1;

	for (int index = 0; index < MAX_DNS_COUNT; index++) {
		if (dns_servers[index] == 0)
			continue;
		
		int socket_fd = socket(AF_INET,SOCK_DGRAM,0);
		if (socket_fd == -1)
			return -1;
		
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;        /* ipv4 */
	 	addr.sin_port = htons(DNS_PORT);  /* port: DNS  53 */
		addr.sin_addr.s_addr = dns_servers[index];/* dns ip has been a network format */
		bzero(&(addr.sin_zero), 8);

		if (timeout.tv_sec == 0 && timeout.tv_usec == 0)
			timeout.tv_sec = DEFAULT_TIME_OUT;
			
		FD_ZERO(&inset);
	  	FD_SET(socket_fd, &inset);

		/* dns query init */
		int dns_packet_len = 0;
		bzero(upd_send_buf, sizeof(upd_send_buf));
		bzero(upd_recv_buf, sizeof(upd_recv_buf));
		
		head = (dns_head_t*)upd_send_buf;
		/* fill head */
		dns_packet_len += create_dns_query_head(head);
		/* fill query */
		unsigned char *query =(unsigned char*)&upd_send_buf[sizeof(dns_head_t)];
		dns_packet_len += create_hostname_foramt(hostname,query);

		type_and_class_t *qtc = (type_and_class_t*)&upd_send_buf[dns_packet_len];
		qtc->type = htons(1);  /* the ipv4 address: A */
		qtc->tclass = htons(1); /* its internet (lol) */
		dns_packet_len += sizeof(type_and_class_t);
		
		sendto(socket_fd, upd_send_buf, dns_packet_len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr));
		if (select(socket_fd + 1, &inset, NULL, NULL, &timeout) != -1) {
			if (FD_ISSET(socket_fd, &inset)) {
				if ((dns_packet_len = recv(socket_fd, upd_recv_buf, sizeof(upd_recv_buf), 0)) > 0) {
					/* parse the dns answer */
					head = (dns_head_t*)upd_recv_buf;
					/* skip head and query field */
					unsigned char *answer_buff = (unsigned char*)&upd_recv_buf[sizeof(dns_head_t) + (strlen((const char*)query)+1) + sizeof(type_and_class_t)];
#if DEBUG_PRINT
					printf("Received.");
					printf("\nThe response contains : ");
					printf("\n %d Questions.",ntohs(head->q_count));
					printf("\n %d Answers.",ntohs(head->ans_count));
					printf("\n %d Authoritative Servers.",ntohs(head->auth_count));
					printf("\n %d Additional records.\n\n",ntohs(head->add_count));
#endif
					/* reading answers */
					int stop = 0;
					for (int i = 0; i < ntohs(head->ans_count); i++) {
						answers[i].name = get_query_hostname(answer_buff, upd_recv_buf, &stop);
						answer_buff = answer_buff + 2;/* skip the 2 byte: 0xc00c */
						
						memcpy((unsigned char*)&(answers[i].type), answer_buff, sizeof(unsigned short));
						answer_buff = answer_buff + sizeof(unsigned short);
						
						memcpy((unsigned char *)&(answers[i].tclass), answer_buff, sizeof(unsigned short));
						answer_buff = answer_buff + sizeof(unsigned short);
						
						memcpy((unsigned char *)&(answers[i].ttl), answer_buff, sizeof(unsigned int));
						answer_buff = answer_buff + sizeof(unsigned int);
						
						memcpy((unsigned char *)&(answers[i].data_len), answer_buff, sizeof(unsigned short));
						answer_buff = answer_buff + sizeof(unsigned short);
						/* answer_buff = answer_buff + sizeof(struct R_DATA); */
					
						if (ntohs(answers[i].type) == 1) {
							/* if its an ipv4 address */
							memcpy((unsigned char *)&answers[i].rdata, answer_buff, ntohs(answers[i].data_len));
							answer_buff = answer_buff + ntohs(answers[i].data_len);
						} else {
							/* for more case....*/
							answers[i].rdata = (long int)get_query_hostname(answer_buff, (unsigned char*)upd_recv_buf, &stop);
							answer_buff = answer_buff + stop;
						}
						
					}

					struct sockaddr_in a;
					for (int i = 0; i < ntohs(head->ans_count); i++) {
					/*
					https://www.ietf.org/rfc/rfc1035.txt
					3.2.2. TYPE values
					
					TYPE fields are used in resource records.  Note that these types are a
					subset of QTYPEs.
					
					TYPE			value and meaning
					
					A				1 a host address
					
					NS				2 an authoritative name server
					
					MD				3 a mail destination (Obsolete - use MX)
					
					MF				4 a mail forwarder (Obsolete - use MX)
					
					CNAME			5 the canonical name for an alias
					
					SOA 			6 marks the start of a zone of authority
					
					MB				7 a mailbox domain name (EXPERIMENTAL)
					
					MG				8 a mail group member (EXPERIMENTAL)
					
					MR				9 a mail rename domain name (EXPERIMENTAL)
					
					NULL			10 a null RR (EXPERIMENTAL)
					
					WKS 			11 a well known service description
					
					PTR 			12 a domain name pointer
					
					HINFO			13 host information
					
					MINFO			14 mailbox or mail list information
					
					MX				15 mail exchange
					
					TXT 			16 text strings
					*/
						if (ntohs(answers[i].type) == 1) {
							/* IPv4 address */
							//if (i == 0) 
							{
								/* only return the first IP entry. */
								resp_infor->type = ntohs(answers[i].type);
								resp_infor->tclass = ntohs(answers[i].tclass);
								a.sin_addr.s_addr=answers[i].rdata;
								safe_strncpy((resp_infor->strIp), inet_ntoa(a.sin_addr), sizeof(resp_infor->strIp));
								break;
							}
						}
						free(answers[i].name);
					}
					if (resp_infor->type == 1 && resp_infor->tclass == 1 && inet_aton(resp_infor->strIp, &addr.sin_addr) > 0)
						ret = 0;
				}
			}
		}
		close(socket_fd);
		if (ret == 0) {
			break;
		}
	}

	if (ret == 0)//successfully
		syslog(LOG_USER | LOG_DEBUG, "LG4_get_hostbyname for the host: %s, ip is %s.", hostname, resp_infor->strIp);
	else
		syslog(LOG_USER | LOG_DEBUG, "LG4_get_hostbyname for the host: %s, Can't get its IP address.", hostname);

	return ret;
}


const char * inet_ntoa_r(struct in_addr ip, char *destaddr,int size)
{
	char *src_addr =(char *) &((struct sockaddr_in *)&ip)->sin_addr;

	static const char *fmt = "%u.%u.%u.%u";
	char tmp[sizeof("255.255.255.255")] = {0};
	int len = snprintf(tmp, sizeof tmp, fmt, src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
	if (len >= size) {
		return (NULL);
	}
	memcpy(destaddr, tmp, len + 1);

	return (destaddr);
}


int get_remoteaddr_by_fd(int fd, struct sockaddr_in *remote_addr)
{
	int ret = -1;
	//char remote_ip[64] = {0};

	socklen_t remote_len = sizeof(*remote_addr);
	ret = getpeername(fd, (sockaddr*)remote_addr, &remote_len);

	//inet_ntop(AF_INET, &(remote_addr->sin_addr), remote_ip, sizeof(remote_ip)); 
	//printf("----->Remote IP %s:%d\n", remote_ip, ntohs(remote_addr->sin_port)); 

	return ret;
}


int get_localaddr_by_fd(int fd, struct sockaddr_in *local_addr)
{
	int ret = -1;
	//char local_ip[64] = {0};

	socklen_t local_len = sizeof(*local_addr);
	ret = getsockname(fd, (sockaddr*)local_addr, &local_len);

	//inet_ntop(AF_INET, &(local_addr->sin_addr), local_ip, sizeof(local_ip));
	//printf("---->Local IP %s:%d\n", local_ip, ntohs(local_addr->sin_port)); 

	return ret;
}


