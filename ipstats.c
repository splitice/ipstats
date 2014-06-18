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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>

struct byte_packet_counter {
	u_int32_t bytes;
	u_int32_t packets;
};

struct ipstat_directional_counters {
	byte_packet_counter gre;
	byte_packet_counter ipip;
	byte_packet_counter tcp;
	byte_packet_counter udp;
	byte_packet_counter ipsec;
	byte_packet_counter other;
};

struct ipstat_counters {
	u_int32_t ip;
	ipstat_directional_counters in;
	ipstat_directional_counters out;
};

uint16_t hostorder_ip;


struct nread_ip {
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
	struct  in_addr ip_src, ip_dst;  /* source and dest address   */
};

//#define ADDR_TO_UINT(x) *(unsigned int*)&(x)
#define ADDR_TO_UINT(x) x

//Hash lookup
unsigned int hash_key = 0;
unsigned int hash_slots;
ipstat_counters* hash_buckets;


//Packet counting
u_int16_t packet_counter = 0;
u_int16_t packet_output_count = 0;
unsigned int next_time = 0;
#define TIME_INTERVAL 10

//PCAP
char errbuf[PCAP_ERRBUF_SIZE];

void output_stats(){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (tv.tv_sec < next_time){
		packet_output_count += 100;
		return;
	}

	//Next time to do work
	next_time = tv.tv_sec + TIME_INTERVAL;
	packet_output_count -= 100;
	
	for (int i = 0; i < hash_slots; i++) {
		ipstat_counters& c = hash_buckets[i];
		
		//empty bucket
		if (c.ip == 0)
			continue;

		u_int32_t ip = c.ip;

		//IP TCP UDP GRE IPIP IPSEC OTHER
		printf("IN %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, 
			c.in.tcp.packets, c.in.tcp.bytes, c.in.udp.packets, c.in.udp.bytes, c.in.gre.packets, c.in.gre.bytes,
			c.in.ipip.packets, c.in.ipip.bytes, c.in.ipsec.packets, c.in.ipsec.bytes, c.in.other.packets, c.in.other.bytes);
		printf("OUT %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
			c.out.tcp.packets, c.out.tcp.bytes, c.out.udp.packets, c.out.udp.bytes, c.out.gre.packets, c.out.gre.bytes,
			c.out.ipip.packets, c.out.ipip.bytes, c.out.ipsec.packets, c.out.ipsec.bytes, c.out.other.packets, c.out.other.bytes);
	}
}

inline void increment_counter(byte_packet_counter& counter, u_int16_t length){
	counter.packets++;
	counter.bytes += length;
}

inline void increment_direction(u_int8_t protocol, ipstat_directional_counters* counter, u_int16_t length){
	switch (protocol){
	case IPPROTO_TCP:
		increment_counter(counter->tcp, length);
		break;
	case IPPROTO_UDP:
		increment_counter(counter->udp, length);
		break;
	case IPPROTO_GRE:
		increment_counter(counter->gre, length);
		break;
	case IPPROTO_IPIP:
		increment_counter(counter->ipip, length);
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		increment_counter(counter->ipsec, length);
		break;
	default:
		increment_counter(counter->other, length);
		break;
	}
}

void ip_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	const struct nread_ip* ip;   /* packet structure         */
	const struct nread_tcp* tcp; /* tcp structure            */
	u_int length = pkthdr->len;  /* packet header length  */
	u_int off, version;             /* offset, version       */
	u_int16_t len;                        /* length holder         */

	ip = (struct nread_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);
	tcp = (struct nread_tcp*)(packet + sizeof(struct ether_header) +
		sizeof(struct nread_ip));

	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version == 4){
		unsigned int addr_idx = (ADDR_TO_UINT(ip->ip_src) ^ hash_key) % hash_slots;
		ipstat_counters& c = hash_buckets[addr_idx];

		ipstat_directional_counters* counter;

		if (c.ip == 0){
			//Not what we are after, try dst
			addr_idx = (ADDR_TO_UINT(ip->ip_dst) ^ hash_key) % hash_slots;
			ipstat_counters& c2 = hash_buckets[addr_idx];
			
			//Check non-hashed ip and empty slot
			if (c2.ip == 0 || c.ip != ADDR_TO_UINT(ip->ip_dst)){
				return;
			}
			counter = &c2.out;
		}
		else
		{
			//Check non-hashed ip
			if (c.ip != ADDR_TO_UINT(ip->ip_src)){
				return;
			}

			counter = &c.in;
		}

		increment_direction(ip->ip_p, counter, length);
	}
}


void ethernet_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	struct ether_header *eptr = (struct ether_header *) packet;

	if (eptr->ether_type == hostorder_ip) {
		ip_handler(pkthdr, packet);

		if ((++packet_counter) == packet_output_count){
			output_stats();
			packet_counter = 0;
		}
	}
	//else: dont care
}

void load_hash_buckets(u_int16_t num_counters, unsigned int* counters)
{
	bool loaded = false;

	//Starting values
	hash_key = 0x17ac;
	hash_buckets = malloc(sizeof(ipstat_counters)*hash_slots);
	memset(hash_buckets, 0, sizeof(ipstat_counters)* hash_slots);

	//Loop until solution found
	while (!loaded){
		//Iterate hash_key, for a different solution
		hash_key++;

		//overflowed, increase slots.
		if (hash_key == 0x17ac){
			free(hash_buckets);
			hash_slots++;
			hash_buckets = malloc(sizeof(ipstat_counters)*hash_slots);
			memset(hash_buckets, 0, sizeof(ipstat_counters)* hash_slots);
		}

		//Zero buckets
		for (int i = hash_slots; i != 0; i--){
			hash_buckets[i].ip = 0;
		}

		//Attempt to find a solution
		loaded = true;
		for (int i = 0; i < num_counters; i++) {
			unsigned int c = counters[i];
			unsigned int addr_idx = (c ^ hash_key) % hash_slots;
			if (hash_buckets[addr_idx].ip != 0){
				loaded = false;
				break;
			}
			hash_buckets[addr_idx].ip = c;
		}
	}
}

int load_devs(const char* name){
	u_int16_t num_counters;
	unsigned int* counters;

	pcap_if_t *alldevs;
	int status = pcap_findalldevs(&alldevs, errbuf);
	if (status != 0) {
		printf("%s\n", errbuf);
		return 1;
	}

	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
		if (strcmp(d->name, name) == 0){
			num_counters = 0;
			for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
				if (a->addr->sa_family == AF_INET){
					num_counters++;
				}
			}
			hash_slots = num_counters * 2.5;
			counters = malloc(sizeof(unsigned int*)* num_counters);
			int i = 0;
			for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
				if (a->addr->sa_family == AF_INET){
					unsigned int addr = ADDR_TO_UINT(((struct sockaddr_in*)a->addr)->sin_addr);
					counters[i] = addr;
					i++;
				}
			}
			break;
		}
	}

	pcap_freealldevs(alldevs);

	load_hash_buckets(num_counters, counters);

	free(counters);
}

int main(int argc, char **argv)
{
	int i;
	char *dev;
	pcap_t* descr;

	if (argc != 2){ printf("Usage: %s device\n", argv[0]); return 0; }

	/* grab a device to peak into... */
	dev = argv[1];
	load_devs(dev);

	printf("# Init complete. Starting\n");

	/* open device for reading */
	descr = pcap_open_live(dev, 200, 0, 1000, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf); exit(1);
	}

	pcap_setnonblock(descr, false, errbuf);

	//pcap_setdirection(descr,PCAP_D_IN)

	hostorder_ip = ntohs(ETHERTYPE_IP);

	struct pcap_pkthdr* pkthdr;
	const u_char* packet;

	int res;
	while ((res = pcap_next_ex(descr, &pkthdr, &packet)) >= 0)
	{
		ethernet_handler(pkthdr, packet);
	}

	fprintf(stdout, "\nDone. Closing!\n");
	return 0;
}