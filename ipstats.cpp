#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#ifdef LINUX
#include <netinet/ether.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pfring.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <stddef.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <map>
#include <set>
#include <math.h>
#include "ip_address.h"
#include "MurmurHash3.h"

/* Structure for conting bytes and packets */
typedef struct byte_packet_counter_s {
	u_int32_t bytes;
	u_int32_t packets;
} byte_packet_counter;

/* Counters for bytes/packets tranferred in a direction */
typedef struct ipstat_directional_counters_s {
	byte_packet_counter gre;
	byte_packet_counter ipip;
	byte_packet_counter tcp;
	byte_packet_counter udp;
	byte_packet_counter icmp;
	byte_packet_counter ipsec;
	byte_packet_counter other;
} ipstat_directional_counters;

/* A statistical entry */
typedef struct ipstat_entry_s {
	ipstat_directional_counters in;
	ipstat_directional_counters out;
	struct ip_address ip;
} ipstat_entry;

typedef struct eth_def_s
{
	pfring* ring;
	unsigned char mac[6];
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

//Packet helpers
uint16_t hostorder_ipv4;
uint16_t hostorder_ipv6;

//Hash lookup
#define PAGES 65536
ipstat_entry *sentinel[PAGES] = { 0 };  // sentinel page, initialized to NULLs.
ipstat_entry ** pages[PAGES];  // list of pages,
                              // initialized so every element points to sentinel

//Packet counting
u_int16_t packet_counter = 0; 
u_int16_t packet_output_count = 1;//Start by outputting empty counters after the first packet
time_t next_time = 0;

#define TIME_INTERVAL 30
#define PACKET_SAMPLING_RATE 5

#ifdef PACKET_SAMPLING_RATE
#define PACKET_INCREMENT PACKET_SAMPLING_RATE
#else
#define PACKET_INCREMENT 1
#endif

/* Hash an IPv6 address */
uint32_t ipv6_hash(const ipv6_address& ip){
	uint32_t* thirtytwos = (uint32_t*)&ip;
	return thirtytwos[0] ^ thirtytwos[1] ^ thirtytwos[2] ^ thirtytwos[3];
}


/* Output stats */
void output_stats(){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (tv.tv_sec < next_time){
		packet_output_count += 100;
		return;
	}
	else{
		packet_output_count -= 50;
	}

	//Next time to do work
	next_time = tv.tv_sec + TIME_INTERVAL;
	packet_counter = 0;
	
	int written = printf("#DIRECTION IP TCP UDP GRE IPIP ICMP IPSEC OTHER\n");
	if (written < 0){
		exit(2);
	}
	
	//Output for every IP (IN+OUT)
	for (int i = 0; i < PAGES; i++) {
		ipstat_entry** p = pages[i];
		if (p == sentinel)
		{
			continue;
		}
		for (int f = 0; f < PAGES; f++)
		{
			ipstat_entry* c = pages[i][f];
			if (c == NULL) continue;
			
			const char* ip = ip_to_string(c->ip);

			//DIR TCP UDP GRE IPIP ICMP IPSEC OTHER
			printf("IN %s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",
				ip,
				c->in.tcp.packets,
				c->in.tcp.bytes,
				c->in.udp.packets,
				c->in.udp.bytes,
				c->in.gre.packets,
				c->in.gre.bytes,
				c->in.ipip.packets,
				c->in.ipip.bytes,
				c->in.icmp.packets,
				c->in.icmp.bytes,
				c->in.ipsec.packets,
				c->in.ipsec.bytes,
				c->in.other.packets,
				c->in.other.bytes);
			printf("OUT %s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",
				ip,
				c->out.tcp.packets,
				c->out.tcp.bytes,
				c->out.udp.packets,
				c->out.udp.bytes,
				c->out.gre.packets,
				c->out.gre.bytes,
				c->out.ipip.packets,
				c->out.ipip.bytes,
				c->out.icmp.packets,
				c->out.icmp.bytes,
				c->out.ipsec.packets,
				c->out.ipsec.bytes,
				c->out.other.packets,
				c->out.other.bytes);
			
			free(c);
		}
		
		free(pages[i]);
		pages[i] = sentinel;
	}
	
	//Flush the output buffer
	fflush(stdout);
}

/* Increment a counter */
inline void increment_counter(byte_packet_counter* counter, u_int16_t length){
	counter->packets += PACKET_INCREMENT;
	counter->bytes += length * PACKET_INCREMENT;
}

/* Increment a counter for a protocol, in a direction */
void increment_direction(u_int8_t protocol, ipstat_directional_counters* counter, u_int16_t length){
	byte_packet_counter* bp;

	switch (protocol){
	case IPPROTO_TCP:
		bp = &counter->tcp;
		break;
	case IPPROTO_UDP:
		bp = &counter->udp;
		break;
	case IPPROTO_GRE:
		bp = &counter->gre;
		break;
	case IPPROTO_IPIP:
		bp = &counter->ipip;
		break;
	case IPPROTO_ICMP:
		bp = &counter->icmp;
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		bp = &counter->ipsec;
		break;
	default:
		bp = &counter->other;
		break;
	}

	increment_counter(bp, length);
}

ipstat_entry** allocate_new_null_filled_page()
{
	ipstat_entry** page = (ipstat_entry**)malloc(sizeof(ipstat_entry*) * PAGES) ;
	memset(page, 0, sizeof(ipstat_entry*) * PAGES);
	return page;
}

/* Handle an IPv4 packet */
void ipv4_handler(const u_char* packet, bool incomming)
{
	const struct ipv4_header* ip;   /* packet structure         */
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	u_int32_t addr_idx;
	ipstat_entry* c;
	ipstat_directional_counters* counter;

	//IP Header
	ip = (struct ipv4_header*)(packet + sizeof(struct ether_header));
	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version != 4){
		return;
	}
	
	struct ipv4_address addr = incomming ? ip->ip_dst : ip->ip_src;

	//Get the src bucket
	addr_idx = IPV4_UINT32(addr);
	c = pages[addr_idx >> 16][addr_idx & 0xFFFF];

	if (c == NULL)
	{
		if (pages[addr_idx >> 16] == sentinel)
		{
			pages[addr_idx >> 16] = allocate_new_null_filled_page();
		}
		c = (ipstat_entry*)malloc(sizeof(ipstat_entry));
		memset(c, 0, sizeof(ipstat_entry));
		c->ip.ver = 4;
		memcpy(&c->ip.v4, &addr, sizeof(addr));
		pages[addr_idx >> 16][addr_idx & 0xFFFF] = c;
	}
	else
	{
		if (c->ip.ver != 4)
		{
			//IPv6 conflict, TODO: handle
			return;
		}
	}
	
	counter = incomming ? &c->in : &c->out;

	increment_direction(ip->ip_p, counter, len);
}

/* Handle an IPv6 Packet */
void ipv6_handler(const u_char* packet, bool incomming)
{
	const struct ipv6_header* ip;   /* packet structure         */
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	ipstat_directional_counters* counter;
	u_int32_t addr_idx;
	ipstat_entry* c;

	//IP Header
	ip = (struct ipv6_header*)(packet + sizeof(struct ether_header));
	len = ntohs(ip->length); /* get packet length */
	version = IP6_V(ip);          /* get ip version    */

	if (version != 6){
		return;
	}
	
	struct ipv6_address addr = incomming ? ip->dst : ip->src;

	//Get the src bucket
	addr_idx = ipv6_hash(addr);
	c = pages[addr_idx >> 16][addr_idx & 0xFFFF];

	if (c == NULL)
	{
		if (pages[addr_idx >> 16] == sentinel)
		{
			pages[addr_idx >> 16] = allocate_new_null_filled_page();
		}
		c = (ipstat_entry*)malloc(sizeof(ipstat_entry));
		memset(c, 0, sizeof(ipstat_entry));
		c->ip.ver = 6;
		memcpy(&c->ip.v6, &addr, sizeof(addr));
		pages[addr_idx >> 16][addr_idx & 0xFFFF] = c;
	}
	else
	{
		if (c->ip.ver != 6 || memcmp(&c->ip.v6,&addr,sizeof(addr)) == 0)
		{
			//IPv6 conflict, TODO: handle
			return;
		}
	}
	
	counter = incomming ? &c->in : &c->out;
	
	increment_direction(ip->next_header, counter, len);
}

/* Handle an ethernet packet */
void ethernet_handler(const u_char* packet, const unsigned char* mac)
{
	struct ether_header *eptr = (struct ether_header *) packet;
	
	bool incomming = false;
	if (memcmp(eptr->ether_dhost, mac, 6) == 0)
	{
		incomming = true;
	}
	else if (memcmp(eptr->ether_shost, mac, 6) != 0)
	{
		//Not a packet for us
		return;
	}

	if (eptr->ether_type == hostorder_ipv4) {
		ipv4_handler(packet, incomming);
	}
	else if (eptr->ether_type == hostorder_ipv6){
		ipv6_handler(packet, incomming);
	}
	else{
		//We have no interest in non IP packets
		return;
	}

	packet_counter++;
	if (packet_counter >= packet_output_count){
		output_stats();
	}
}


pfring* open_pfring(const char* dev){
	int rc;

	pfring* pd = pfring_open(dev, sizeof(ether_header) + sizeof(ipv6_header), PF_RING_DO_NOT_PARSE | PF_RING_DO_NOT_TIMESTAMP);
	if (pd == NULL){
		printf("#Error: A PF_RING error occured while opening %s: %s\n", dev, strerror(errno));
		return NULL;
	}

	rc = pfring_set_direction(pd, rx_and_tx_direction);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while setting direction: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}

	rc = pfring_enable_ring(pd);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while enabling: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}

	rc = pfring_set_poll_watermark(pd, 1024);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while setting the watermark: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}

#ifdef PACKET_SAMPLING_RATE
	rc = pfring_set_sampling_rate(pd, PACKET_SAMPLING_RATE);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while setting sampling rate: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}
#endif

	return pd;
}

void get_mac(const char* name, unsigned char* mac_address)
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	bool success = false;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) { /* handle error*/}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */}

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (!(ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (strcmp(it->ifr_name, name) == 0)
				{
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						success = true;
						break;
					}
				}
			}
		}
		else { /* handle error */}
	}

	if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
}

/* Process packets using PF_RING */
void run_pfring(const char** dev, int ndev)
{
	u_char* buffer;
	pfring_pkthdr hdr;
	int epfd;
	struct epoll_event event;
	struct epoll_event events[4];
	std::map<int, eth_def> fd_map;
	bool running = true;
	int res;

	epfd = epoll_create1(0);
	if (epfd == -1)
	{
		perror("#Error: epoll_create");
		return;
	}	

	for (int i = 0; i < ndev; i++){
		pfring* pd = open_pfring(dev[i]);
		int sfd = pfring_get_selectable_fd(pd);

		event.data.fd = sfd;
		event.events = EPOLLOUT | EPOLLIN;
		res = epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &event);
		if (res == -1)
		{
			perror("#Error: epoll_ctl add failed");
			return;
		}
		
		eth_def eth;
		eth.ring = pd;
		get_mac(dev[i], eth.mac);
		
		fd_map[sfd] = eth;
	}

	while (running){
		int n = epoll_wait(epfd, events, 4, 500);
		for (int i = 0; i < n; i++)
		{
			eth_def eth = fd_map[events[i].data.fd];
			int rc = pfring_recv(eth.ring, &buffer, 0, &hdr, 0);
			if (rc == 0)
			{
				continue;
			}
			else if (rc > 0)
			{
				ethernet_handler(buffer, eth.mac);
			}
			else
			{
				printf("#Error: A PF_RING error occured while recving: %s rc:%d\n", strerror(errno), rc);
				running = false;
				break;
			}
		}
	}

	for (std::map<int, eth_def>::iterator it = fd_map.begin(); it != fd_map.end(); it++) {
		pfring_close(it->second.ring);
	}
	
	close(epfd);
}

/* It all starts here */
int main(int argc, char **argv)
{
	char *dev;

	if (argc < 2){ printf("Usage: %s [devices] ...\n", argv[0]); return 1; }
	
	for (int i = 0; i < PAGES; i++)
	{
		pages[i] = sentinel;
	}

	//ethernet type
	hostorder_ipv4 = ntohs(ETHERTYPE_IP);
	hostorder_ipv6 = ntohs(ETHERTYPE_IPV6);

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("# Init complete. Starting\n");

	run_pfring((const char**)(argv + 1), argc - 1);

	return 0;
}