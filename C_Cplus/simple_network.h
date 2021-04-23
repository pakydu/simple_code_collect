#ifndef _SIMPLE_NETWORK_H_
#define _SIMPLE_NETWORK_H_

#ifdef __cplusplus
extern "C"
{
#endif



#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef MAX_IPADDR_LEN
#define MAX_IPADDR_LEN 16
#endif

#ifndef MAX_DNS_COUNT
#define MAX_DNS_COUNT 2
#endif

#ifndef MAX_IFNAME_LEN
#define MAX_IFNAME_LEN 16
#endif

#ifndef MAX_IP_COUNT
#define MAX_IP_COUNT       2
#endif

#ifndef MAX_IPNAME_LEN
#define MAX_IPNAME_LEN        64
#endif

#ifndef MAX_MACADDR_LEN
#define MAX_MACADDR_LEN       18
#endif


#define DNS_PORT  53
#define DEFAULT_TIME_OUT  10   //- seconds


/*
 * Decode message and generate answer
 */
/* RFC 1035
...
Whenever an octet represents a numeric quantity, the left most bit
in the diagram is the high order or most significant bit.
That is, the bit labeled 0 is the most significant bit.
...

4.1.1. Header section format
      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   OPCODE  |AA|TC|RD|RA| 0  0  0|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
ID      16 bit random identifier assigned by querying peer.
        Used to match query/response.
QR      message is a query (0), or a response (1).
OPCODE  0   standard query (QUERY)
        1   inverse query (IQUERY)
        2   server status request (STATUS)
AA      Authoritative Answer - this bit is valid in responses.
        Responding name server is an authority for the domain name
        in question section. Answer section may have multiple owner names
        because of aliases.  The AA bit corresponds to the name which matches
        the query name, or the first owner name in the answer section.
TC      TrunCation - this message was truncated.
RD      Recursion Desired - this bit may be set in a query and
        is copied into the response.  If RD is set, it directs
        the name server to pursue the query recursively.
        Recursive query support is optional.
RA      Recursion Available - this be is set or cleared in a
        response, and denotes whether recursive query support is
        available in the name server.
RCODE   Response code.
        0   No error condition
        1   Format error
        2   Server failure - server was unable to process the query
            due to a problem with the name server.
        3   Name Error - meaningful only for responses from
            an authoritative name server. The referenced domain name
            does not exist.
        4   Not Implemented.
        5   Refused.
QDCOUNT number of entries in the question section.
ANCOUNT number of records in the answer section.
NSCOUNT number of records in the authority records section.
ARCOUNT number of records in the additional records section.

4.1.2. Question section format

The section contains QDCOUNT (usually 1) entries, each of this format:
      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
QNAME   a domain name represented as a sequence of labels, where
        each label consists of a length octet followed by that
        number of octets. The domain name terminates with the
        zero length octet for the null label of the root. Note
        that this field may be an odd number of octets; no
        padding is used.
QTYPE   a two octet type of the query.
          1 a host address [REQ_A const]
          2 an authoritative name server
          3 a mail destination (Obsolete - use MX)
          4 a mail forwarder (Obsolete - use MX)
          5 the canonical name for an alias
          6 marks the start of a zone of authority
          7 a mailbox domain name (EXPERIMENTAL)
          8 a mail group member (EXPERIMENTAL)
          9 a mail rename domain name (EXPERIMENTAL)
         10 a null RR (EXPERIMENTAL)
         11 a well known service description
         12 a domain name pointer [REQ_PTR const]
         13 host information
         14 mailbox or mail list information
         15 mail exchange
         16 text strings
       0x1c IPv6?
        252 a request for a transfer of an entire zone
        253 a request for mailbox-related records (MB, MG or MR)
        254 a request for mail agent RRs (Obsolete - see MX)
        255 a request for all records
QCLASS  a two octet code that specifies the class of the query.
          1 the Internet
        (others are historic only)
        255 any class

4.1.3. Resource Record format

The answer, authority, and additional sections all share the same format:
a variable number of resource records, where the number of records
is specified in the corresponding count field in the header.
Each resource record has this format:
      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                                               /
    /                      NAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
NAME    a domain name to which this resource record pertains.
TYPE    two octets containing one of the RR type codes.  This
        field specifies the meaning of the data in the RDATA field.
CLASS   two octets which specify the class of the data in the RDATA field.
TTL     a 32 bit unsigned integer that specifies the time interval
        (in seconds) that the record may be cached.
RDLENGTH a 16 bit integer, length in octets of the RDATA field.
RDATA   a variable length string of octets that describes the resource.
        The format of this information varies according to the TYPE
        and CLASS of the resource record.
        If the TYPE is A and the CLASS is IN, it's a 4 octet IP address.

4.1.4. Message compression

In order to reduce the size of messages, domain names coan be compressed.
An entire domain name or a list of labels at the end of a domain name
is replaced with a pointer to a prior occurance of the same name.

The pointer takes the form of a two octet sequence:
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
The first two bits are ones.  This allows a pointer to be distinguished
from a label, since the label must begin with two zero bits because
labels are restricted to 63 octets or less.  The OFFSET field specifies
an offset from the start of the message (i.e., the first octet
of the ID field in the domain header).
A zero offset specifies the first byte of the ID field, etc.
Domain name in a message can be represented as either:
   - a sequence of labels ending in a zero octet
   - a pointer
   - a sequence of labels ending with a pointer
 */

/*
 * example: hostname network foramt
 * text: baidu.com: type A, class IN
 * hex:  05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01 .baidu.com.....
 */

#pragma pack(push, 1)
enum
{
	DEFAULT_TTL = 120,    /* can tweak this */
	MAX_PACK_LEN = 512, /* cannot get bigger packets than 512 per RFC1035. */
	IP_STRING_LEN = sizeof(".xxx.xxx.xxx.xxx"),
	MAX_NAME_LEN = IP_STRING_LEN - 1 + sizeof(".in-addr.arpa"),
	REQ_A = 1,
	REQ_PTR = 12,
};

/* the message from client and first part of response msg */
typedef struct dns_head
{
	unsigned short id;		    // identification number
	
	unsigned int rd     :1;		// recursion desired
	unsigned int tc     :1;		// truncated message
	unsigned int aa     :1;		// authoritive answer
	unsigned int opcode :4;	    // purpose of message
	unsigned int qr     :1;		// query/response flag
	
	unsigned int rcode  :4;	    // response code
	unsigned int cd     :1;	    // checking disabled
	unsigned int ad     :1;	    // authenticated data
	unsigned int z      :1;		// its z! reserved
	unsigned int ra     :1;		// recursion available
	
	unsigned short q_count;	    // number of question entries
	unsigned short ans_count;	// number of answer entries
	unsigned short auth_count;	// number of authority entries
	unsigned short add_count;	// number of resource entries
} dns_head_t;

/* Structure used to access type and class fields.
 * They are totally unaligned, but gcc 4.3.4 thinks that pointer of type unsigned short int*
 * is 16-bit aligned and replaces 16-bit memcpy (in move_from_unaligned16 macro)
 * with aligned halfword access on arm920t!
 * Oh well. Slapping PACKED everywhere seems to help: 
 */
typedef struct type_and_class 
{
	unsigned short int type;   /* host address type: A(0x01) for IPv4, AAAA(0x1c) for IPv6*/
	unsigned short int tclass; /* 1 for tclass INET */
} type_and_class_t;

//- Pointers to resource record contents
typedef struct dns_res_record
{
	unsigned char  *name;    /* deamon name */
	unsigned short type;     /* host address type: A(0x01) for IPv4, AAAA(0x1c) for IPv6 */
	unsigned short tclass;   /* 1 for class INET */
	unsigned int   ttl;      /* time to live: number second */
	unsigned short data_len; /* ip address length. IPv4 the length is 4,IPv6 the length is 16 */
	unsigned int   rdata;    /* IP address */
} dns_res_record_t;

//- for LG4_gethostbyname result data.
typedef struct dns_answer
{
	unsigned short type;
	unsigned short tclass;
	char strIp[IP_STRING_LEN*4];
} dns_answer_t;

#pragma pack(pop)

int get_ipConfig_by_systemfile(const char *if_name, int *dhcp, unsigned int *ip_addr, unsigned int *net_mask, unsigned int *gw);
int set_ipConfig_by_systemfile(const char *if_name, int dhcp, unsigned int ip_addr, unsigned int net_mask, unsigned int gw);


int get_mac_address(const char *eth_name, unsigned char mac[6], char *fmt_buf);

int get_ip_address(const char *eth_name, char *ip_buf);
int get_broadcast_address(const char *eth_name, char *bcast_buf);
int get_subnet_mask(const char *eth_name, char *mask_buf);
int get_gateway(const char *eth_name, char *gw_buf);
int get_system_DNS(int count, unsigned int dns[]);
int get_ip_mode(const char *eth_name);//dhcp or static


int get_hostbyname(const char *hostname, struct timeval timeout, dns_answer_t *resp_infor);
const char * inet_ntoa_r(struct in_addr ip, char *destaddr,int size);

int get_remoteaddr_by_fd(int fd, struct sockaddr_in *remote_addr);
int get_localaddr_by_fd(int fd, struct sockaddr_in *local_addr);




#ifdef __cplusplus
}
#endif

#endif
