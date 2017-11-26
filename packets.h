#pragma once



typedef struct eth_def_s
{
	pfring* ring;
	unsigned char mac[6];
	bool zc;
	uint32_t sampling_rate;
} eth_def;

//Structure of an IP packet
struct ipv4_header {
	u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
	u_int8_t        ip_tos;          /* type of service           */
	u_int16_t       ip_len;          /* total length              */
	u_int16_t       ip_id;           /* identification            */
	u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
	u_int8_t        ip_ttl;          /* time to live              */
	u_int8_t        ip_p;            /* protocol                  */
	u_int16_t       ip_sum;          /* checksum                  */
	struct  ipv4_address ip_src, ip_dst;  /* source and dest address   */
};

struct ipv6_header
{
	uint32_t        ip_vtcfl;	/* version then traffic class and flow label */
#define IP6_V(ip)		(ntohl((ip)->ip_vtcfl) >> 28)
	uint16_t length;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct ipv6_address src;
	struct ipv6_address dst;
};