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

class ipstat_directional_counters {
public:
	unsigned long gre_packets;
	unsigned long gre_bytes;

	unsigned long ipip_packets;
	unsigned long ipip_bytes;

	unsigned long tcp_packets;
	unsigned long tcp_bytes;

	unsigned long udp_packets;
	unsigned long udp_bytes;

	unsigned long ipsec_packets;
	unsigned long ipsec_bytes;

	unsigned long other_packets;
	unsigned long other_bytes;

	ipstat_directional_counters(){
		gre_packets = 0;
		gre_bytes = 0;
		ipip_packets = 0;
		ipip_bytes = 0;
		tcp_packets = 0;
		tcp_bytes = 0;
		udp_packets = 0;
		udp_bytes = 0;
		ipsec_packets = 0;
		ipsec_bytes = 0;
		other_packets = 0;
		other_bytes = 0;
	}
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

int packet_counter = 0;
char errbuf[PCAP_ERRBUF_SIZE];
unsigned int hash_key = 0;
ipstat_counters* hash_buckets[HASH_BUCKET_SLOTS];
std::vector<ipstat_counters*> counters;

void output_stats(){
	 for (std::vector<ipstat_counters*>::iterator iterator = counters.begin(); iterator != counters.end(); iterator++) {
		ipstat_counters* counters = *iterator;
		unsigned int ip = counters->ip;

		//IP TCP UDP GRE IPIP IPSEC OTHER
		printf("IN %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, 
			counters->in.tcp_packets, counters->in.tcp_bytes, counters->in.udp_packets, counters->in.udp_bytes, counters->in.gre_packets, counters->in.gre_bytes,
			counters->in.ipip_packets, counters->in.ipip_bytes, counters->in.ipsec_packets, counters->in.ipsec_bytes, counters->in.other_packets, counters->in.other_bytes);
		printf("OUT %d.%d.%d.%d %d %d %d %d %d %d %d %d %d %d %d %d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF,
			counters->out.tcp_packets, counters->out.tcp_bytes, counters->out.udp_packets, counters->out.udp_bytes, counters->out.gre_packets, counters->out.gre_bytes,
			counters->out.ipip_packets, counters->out.ipip_bytes, counters->out.ipsec_packets, counters->out.ipsec_bytes, counters->out.other_packets, counters->out.other_bytes);
	}
}

void increment_counter(u_int8_t protocol, ipstat_directional_counters* counter, int length){
	if (protocol == IPPROTO_TCP)
	{
		counter->tcp_packets++;
		counter->tcp_bytes += length;
	}
	else if (protocol == IPPROTO_UDP)
	{
		counter->udp_packets++;
		counter->udp_bytes += length;
	}
	else if (protocol == IPPROTO_GRE)
	{
		counter->gre_packets++;
		counter->gre_bytes += length;
	}
	else if (protocol == IPPROTO_IPIP)
	{
		counter->ipip_packets++;
		counter->ipip_bytes += length;
	}
	else if (protocol == IPPROTO_ESP || protocol == IPPROTO_AH)
	{
		counter->ipsec_packets++;
		counter->ipsec_bytes += length;
	}
	else
	{
		counter->other_packets++;
		counter->other_bytes += length;
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

		increment_counter(ip->ip_p, counter, length);
	}
}

/* callback function that is passed to pcap_loop(..) and called each time
* a packet is recieved                                                    */
void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*
	packet)
{
	u_int caplen = pkthdr->caplen; /* length of portion present from bpf  */
	u_int length = pkthdr->len;    /* length of this packet off the wire  */
	struct ether_header *eptr;     /* net/ethernet.h                      */
	u_short ether_type;            /* the type of packet (we return this) */
	eptr = (struct ether_header *) packet;
	ether_type = ntohs(eptr->ether_type);

	if (ether_type == ETHERTYPE_IP) {
		ip_handler(pkthdr, packet);
	}
	//else: dont care

	packet_counter++;
	if ((packet_counter % OUTPUT_EVERY_PACKETS) == 0){
		output_stats();
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
	descr = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (descr == NULL)
	{
		printf("pcap_open_live(): %s\n", errbuf); exit(1);
	}

	pcap_loop(descr, -1, my_callback, NULL);

	fprintf(stdout, "\nDone. Closing!\n");
	return 0;
}