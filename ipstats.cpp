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
#include <pcap.h>
#ifdef USE_PF_RING
#include <pfring.h>
#endif
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
	struct ip_address ip;
	ipstat_directional_counters in;
	ipstat_directional_counters out;
} ipstat_entry;

//Structure of an IP packet
struct nread_ipv4 {
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
#define HASH_KEY_INIT -1
uint32_t hash_key = HASH_KEY_INIT;
uint32_t hash_slots;
ipstat_entry* hash_buckets;

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

/* Hash function for integer distribution */
uint32_t ipv4_hash(ipv4_address ip, uint32_t hash_key) {
	uint32_t x = *(uint32_t*)&ip;
	if (hash_key == 0){
		return x;
	}

	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x);
	return x * hash_key;
}

/* Hash an IPv6 address */
uint32_t ipv6_hash(const ipv6_address& ip, uint32_t hash_key){
	uint32_t ret;
	MurmurHash3_x86_32(&ip, sizeof(ipv6_address), hash_key, &ret);
	return ret;
}

/* Hash an IP address */
uint32_t ip_hash(const struct ip_address& ip, uint32_t hash_key){
	if (ip.ver == 4){
		return ipv4_hash(ip.v4, hash_key);
	}
	else if (ip.ver == 6){
		return ipv6_hash(ip.v6, hash_key);
	}
	return 0;
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
	for (int i = 0; i < hash_slots; i++) {
		ipstat_entry& c = hash_buckets[i];
		
		//empty bucket
		if (c.ip.ver == 0)
			continue;

		const char* ip = ip_to_string(c.ip);

		//DIR TCP UDP GRE IPIP ICMP IPSEC OTHER
		printf("IN %s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n", ip,
			c.in.tcp.packets, c.in.tcp.bytes, c.in.udp.packets, c.in.udp.bytes, c.in.gre.packets, c.in.gre.bytes,
			c.in.ipip.packets, c.in.ipip.bytes, c.in.icmp.packets, c.in.icmp.bytes, c.in.ipsec.packets, c.in.ipsec.bytes,
			c.in.other.packets, c.in.other.bytes);
		printf("OUT %s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n", ip,
			c.out.tcp.packets, c.out.tcp.bytes, c.out.udp.packets, c.out.udp.bytes, c.out.gre.packets, c.out.gre.bytes,
			c.out.ipip.packets, c.out.ipip.bytes, c.out.icmp.packets, c.out.icmp.bytes, c.out.ipsec.packets, c.out.ipsec.bytes,
			c.out.other.packets, c.out.other.bytes);
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

/* Handle an IPv4 packet */
void ipv4_handler(const u_char* packet)
{
	const struct nread_ipv4* ip;   /* packet structure         */
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	u_int32_t addr_idx;
	ipstat_entry* c;
	ipstat_directional_counters* counter;

	//IP Header
	ip = (struct nread_ipv4*)(packet + sizeof(struct ether_header));
	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version != 4){
		return;
	}

	//Get the src bucket
	addr_idx = ipv4_hash(ip->ip_src, hash_key) % hash_slots;
	c = &hash_buckets[addr_idx];

	if (c->ip.ver != 4 || (*(uint32_t*)&c->ip.v4) != (*(uint32_t*)&ip->ip_src)){
		//Get the dst bucket
		addr_idx = ipv4_hash(ip->ip_dst, hash_key) % hash_slots;
		c = &hash_buckets[addr_idx];
			
		//Check non-hashed ip and empty slot
		if (c->ip.ver == 0 || (*(uint32_t*)&c->ip.v4) != (*(uint32_t*)&ip->ip_dst)){
			return;
		}

		counter = &c->in;
	}
	else
	{
		counter = &c->out;
	}

	increment_direction(ip->ip_p, counter, len);
}

/* Handle an IPv6 Packet */
void ipv6_handler(const u_char* packet)
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

	//Get the src bucket
	addr_idx = ipv6_hash(ip->src, hash_key) % hash_slots;
	c = &hash_buckets[addr_idx];

	if (c->ip.ver != 6 || memcmp(&c->ip.v6, &ip->src, sizeof(ipv6_address)) != 0){
		//Get the dst bucket
		addr_idx = ipv6_hash(ip->dst, hash_key) % hash_slots;
		c = &hash_buckets[addr_idx];

		//Check non-hashed ip and empty slot
		if (c->ip.ver == 0 || memcmp(&c->ip.v6, &ip->dst, sizeof(ipv6_address)) != 0){
			return;
		}

		counter = &c->in;
	}
	else
	{
		counter = &c->out;
	}

	increment_direction(ip->next_header, counter, len);
}

/* Handle an ethernet packet */
void ethernet_handler(const u_char* packet)
{
	struct ether_header *eptr = (struct ether_header *) packet;

	if (eptr->ether_type == hostorder_ipv4) {
		ipv4_handler(packet);
	}
	else if (eptr->ether_type == hostorder_ipv6){
		ipv6_handler(packet);
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

/* Handle an ethernet packet (libpcap callback) */
void pcap_ethernet_handler(u_char* unused, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	ethernet_handler(packet);
}

/* Initialize hash buckets */
void load_hash_buckets(u_int16_t num_counters, struct ip_address* counters)
{
	bool loaded = false;

	//Starting values
	hash_key = HASH_KEY_INIT;
	hash_buckets = (ipstat_entry*)malloc(sizeof(ipstat_entry)*hash_slots);
	memset(hash_buckets, 0, sizeof(ipstat_entry)* hash_slots);

	//Loop until solution found
	while (!loaded){
		//Iterate hash_key, for a different solution
		hash_key++;

		//overflowed, increase slots.
		if (hash_key == HASH_KEY_INIT){
			free(hash_buckets);
			hash_slots++;
			hash_buckets = (ipstat_entry*)malloc(sizeof(ipstat_entry)*hash_slots);
			memset(hash_buckets, 0, sizeof(ipstat_entry)* hash_slots);
		}

		//Zero buckets
		for (int i = 0; i < hash_slots; i++){
			hash_buckets[i].ip.ver = 0;
		}

		//Attempt to find a solution
		loaded = true;
		for (int i = 0; i < num_counters; i++) {
			struct ip_address c = counters[i];
			uint32_t addr_idx = ip_hash(c, hash_key) % hash_slots;
			if (hash_buckets[addr_idx].ip.ver != 0){
				loaded = false;
				break;
			}
			hash_buckets[addr_idx].ip = c;
		}
	}
}

struct ConstCharStarComparator
{
	bool operator()(const char *s1, const char *s2) const
	{
		return strcmp(s1, s2) < 0;
	}
};


/* Calculate an approsimate probability of hash collision */
double approx_birthday_paradox(uint16_t k, uint32_t N){
	return exp(-0.5 * (double)k * ((double)k - 1.0) / (double)N);
}

/* Find our device, load addresses */
bool load_devs(std::set<char*, ConstCharStarComparator> names) {
	u_int16_t num_counters;
	struct ip_address* counters;
	bool found = false;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *alldevs;
	int status = pcap_findalldevs(&alldevs, errbuf);
	if (status != 0) {
		printf("#Error: pcap_findalldevs - %s\n", errbuf);
		return 1;
	}

	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
		if (names.find(d->name) != names.end()) {
			//Count number of addresses (IPv4 & IPv6)
			num_counters = 0;
			for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
				if (a->addr->sa_family == AF_INET) {
					num_counters++;
					hash_slots += 7;
				}
				else if (a->addr->sa_family == AF_INET6) {
					num_counters++;
					hash_slots += 13;
				}
			}
		}
	}

	//Increase hash table with size
	//TODO: Open Addressing or Buckets to scale to thousands
	double probability_estimate = 1;
	for (uint8_t i = 0; i < 6; i++){
		probability_estimate = approx_birthday_paradox(num_counters, hash_slots);
		if (probability_estimate > 0.9995){
			hash_slots *= 2;
		}
	}
			
	//IP Address array
	counters = (struct ip_address*)malloc(sizeof(struct ip_address)* num_counters);

	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
		if (names.find(d->name) != names.end()) {
			//Store all IP addresses
			int i = 0, f = 0;
			for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
				if (a->addr->sa_family == AF_INET || a->addr->sa_family == AF_INET6){
					assert(i <= num_counters);
					sockaddr_to_ip(a->addr, &counters[i]);
					i++;
				}
			}
			found = true;
		}
	}

	pcap_freealldevs(alldevs);

	if (found){
		load_hash_buckets(num_counters, counters);

		free(counters);
	}
	return found;
}

#ifdef USE_PF_RING
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

/* Process packets using PF_RING */
void run_pfring(const char** dev, int ndev)
{
	u_char* buffer;
	pfring_pkthdr hdr;
	int epfd;
	struct epoll_event event;
	struct epoll_event events[16];
	std::map<int, pfring*> fd_map;

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
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &event) == -1)
		{
			perror("#Error: epoll_ctl add failed");
			return;
		}
		fd_map[sfd] = pd;
	}

	while (true){
		int n = epoll_wait(epfd, events, 16, 500);
		for (int i = 0; i < n; i++)
		{
			int rc = pfring_recv(fd_map[events[i].data.fd], &buffer, 0, &hdr, 0);
			if (rc == 0)
			{
				
				continue;
			}
			else if (rc > 0)
			{
				ethernet_handler(buffer);
			}
			else
			{
				printf("#Error: A PF_RING error occured while recving: %s rc:%d\n", strerror(errno), rc);
				return;
			}
		}
	}

	for (std::map<int, pfring*>::iterator it = fd_map.begin(); it != fd_map.end(); it++){
		pfring_close(it->second);
	}
	
	close(epfd);
}
#else
/* Process packets using pcap */
void run_pcap(const char* dev)
{
	pcap_t* descr;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* open device for reading */
	descr = pcap_open_live(dev, 100, 0, 1000, errbuf);
	if (descr == NULL)
	{
		printf("#Error: pcap_open_live(): %s\n", errbuf); exit(1);
	}

	pcap_setnonblock(descr, false, errbuf);

	//pcap_setdirection(descr,PCAP_D_IN)

	struct pcap_pkthdr* pkthdr;
	const u_char* packet;

	while (true)
	{
		pcap_dispatch(descr, 1000, pcap_ethernet_handler, NULL);
	}
}
#endif

/* It all starts here */
int main(int argc, char **argv)
{
	char *dev;

	if (argc < 2){ printf("Usage: %s [devices] ...\n", argv[0]); return 1; }
	
#ifndef USE_PF_RING
	if (argc != 2)
	{
		printf("Compiled with PCAP backend, only supports one device. Patches welcome.\n", argv[0]); return 1;
	}
#endif


	//ethernet type
	hostorder_ipv4 = ntohs(ETHERTYPE_IP);
	hostorder_ipv6 = ntohs(ETHERTYPE_IPV6);

	/* read all devices */
	std::set<char*, ConstCharStarComparator> devs;
	for (int i = 1; i < argc; i++)
	{
		devs.insert(argv[i]);
	}
	
	/* grab a device to peak into... */
	if (!load_devs(devs)) {
		printf("# Init failed, device not found.\n");
		return 1;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("# Init complete. Starting\n");

#ifdef USE_PF_RING
	run_pfring((const char**)(argv + 1), argc - 1);
#else
	run_pcap(argv[1]);
#endif

	return 0;
}