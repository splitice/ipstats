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
#include <vector>

class byte_packet_counter {
public:
	unsigned long bytes;
	unsigned long packets;

	byte_packet_counter(){
		bytes = 0;
		packets = 0;
	}
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
	unsigned int ip;
	ipstat_directional_counters in;
	ipstat_directional_counters out;
};


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

#define OUTPUT_EVERY_PACKETS 1000
#define HASH_BUCKET_SLOTS 500

#define ADDR_TO_UINT(x) *(unsigned int*)&(x)

unsigned int packet_counter = 0;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned int hash_key = 0;
ipstat_counters hash_buckets[HASH_BUCKET_SLOTS];
std::vector<ipstat_counters*> counters;

void output_stats(){
	 for (std::vector<ipstat_counters*>::iterator iterator = counters.begin(); iterator != counters.end(); iterator++) {
		ipstat_counters* counters = *iterator;
		unsigned int ip = counters->ip;

		//IP TCP UDP GRE IPIP IPSEC OTHER
		printf("IN %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, 
			counters->in.tcp.packets, counters->in.tcp.bytes, counters->in.udp.packets, counters->in.udp.bytes, counters->in.gre.packets, counters->in.gre.bytes,
			counters->in.ipip.packets, counters->in.ipip.bytes, counters->in.ipsec.packets, counters->in.ipsec.bytes, counters->in.other.packets, counters->in.other.bytes);
		printf("OUT %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
			counters->out.tcp.packets, counters->out.tcp.bytes, counters->out.udp.packets, counters->out.udp.bytes, counters->out.gre.packets, counters->out.gre.bytes,
			counters->out.ipip.packets, counters->out.ipip.bytes, counters->out.ipsec.packets, counters->out.ipsec.bytes, counters->out.other.packets, counters->out.other.bytes);
	}
}

void increment_counter(byte_packet_counter& counter){
	counter.packets++;
	counter.bytes += length;
}

void increment_direction(u_int8_t protocol, ipstat_directional_counters* counter, int length){
	switch (protocol){
	case IPPROTO_TCP:
		increment_counter(counter->tcp);
		break;
	case IPPROTO_UDP:
		increment_counter(counter->udp);
		break;
	case IPPROTO_GRE:
		increment_counter(counter->gre);
		break;
	case IPPROTO_IPIP:
		increment_counter(counter->ipip);
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		increment_counter(counter->gre);
		break;
	default:
		increment_counter(counter->other);
		break;
	}
}

void ip_handler(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	const struct nread_ip* ip;   /* packet structure         */
	const struct nread_tcp* tcp; /* tcp structure            */
	u_int length = pkthdr->len;  /* packet header length  */
	u_int off, version;             /* offset, version       */
	int len;                        /* length holder         */

	ip = (struct nread_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);
	tcp = (struct nread_tcp*)(packet + sizeof(struct ether_header) +
		sizeof(struct nread_ip));

	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version == 4){
		unsigned int addr_idx = (ADDR_TO_UINT(ip->ip_src) * hash_key) % HASH_BUCKET_SLOTS;
		ipstat_directional_counters* counter;

		if (hash_buckets[addr_idx] == 0){
			//Not what we are after, try dst
			addr_idx = (ADDR_TO_UINT(ip->ip_dst) * hash_key) % HASH_BUCKET_SLOTS;
			if (hash_buckets[addr_idx] == 0){
				return;
			}
			counter = &(hash_buckets[addr_idx]->out);
		}
		else
		{
			counter = &(hash_buckets[addr_idx]->in);
		}

		increment_direction(ip->ip_p, counter, length);
	}
}

/* callback function that is passed to pcap_loop(..) and called each time
* a packet is recieved                                                    */
void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*
	packet)
{
	struct ether_header *eptr;     /* net/ethernet.h                      */
	u_short ether_type;            /* the type of packet (we return this) */
	eptr = (struct ether_header *) packet;
	ether_type = ntohs(eptr->ether_type);

	if (ether_type == ETHERTYPE_IP) {
		ip_handler(pkthdr, packet);
	}
	//else: dont care

	if ((++packet_counter) == OUTPUT_EVERY_PACKETS){
		output_stats();
		packet_counter = 0;
	}
}

void load_hash_buckets()
{
	bool loaded = false;

	while (!loaded){
		//Iterate hash_key, for a different solution
		hash_key++;

		//Zero buckets
		memset(hash_buckets, 0, sizeof(ipstat_counters*)* HASH_BUCKET_SLOTS);

		//Attempt to find a solution
		loaded = true;
		for (std::vector<ipstat_counters*>::iterator iterator = counters.begin(); iterator != counters.end(); iterator++) {
			unsigned int addr_idx = ((*iterator)->ip * hash_key) % HASH_BUCKET_SLOTS;
			if (hash_buckets[addr_idx] != 0){
				loaded = false;
				break;
			}
			hash_buckets[addr_idx] = *iterator;
		}
	}
}

int load_devs(const char* name){
	pcap_if_t *alldevs;
	int status = pcap_findalldevs(&alldevs, errbuf);
	if (status != 0) {
		printf("%s\n", errbuf);
		return 1;
	}

	for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
		if (strcmp(d->name, name) == 0){
			for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
				if (a->addr->sa_family == AF_INET){
					unsigned int addr = ADDR_TO_UINT(((struct sockaddr_in*)a->addr)->sin_addr);
					ipstat_counters* counter = new ipstat_counters();
					counter->ip = addr;
					counters.push_back(counter);
				}
			}
		}
	}

	pcap_freealldevs(alldevs);

	load_hash_buckets();
}

int main(int argc, char **argv)
{
	int i;
	char *dev;
	pcap_t* descr;

	if (argc != 2){ fprintf(stdout, "Usage: %s device\n", argv[0]); return 0; }

	/* grab a device to peak into... */
	dev = argv[1];
	load_devs(dev);

	/* open device for reading */
	descr = pcap_open_live(dev, 200, 0, 1000, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf); exit(1);
	}

	pcap_loop(descr, -1, my_callback, NULL);

	fprintf(stdout, "\nDone. Closing!\n");
	return 0;
}