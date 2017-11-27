#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

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
#include <math.h>
#include <errno.h>
#include "ip_address.h"
#include "packets.h"

#define SAMPLES_DEFAULT_WATERMARK 16
#define SAMPLES_DEFAULT_RATE 5
#define SAMPLES_DESIRED 15000
#define TIME_INTERVAL 15
#define CAPTURE_LENGTH 94
#define PACKET_CAPTURE

#ifdef PACKET_CAPTURE
#define CAPTURE_LENGTH 196
#endif

/* A statistical entry */
typedef struct ipstat_entry_s {
	ipstat_entry_s* next;
	int fd;
	struct ip_address ip;
	bool used;
	bool isnew;
} ipstat_entry;
//Hash lookup
#define PAGES 65536
ipstat_entry *sentinel[PAGES] = { 0 };  // sentinel page, initialized to NULLs.
ipstat_entry ** pages[PAGES];  // list of pages,
                              // initialized so every element points to sentinel

//Packet counting
uint32_t packet_counter = 0; 
uint32_t packet_output_count = 1;
time_t next_time = 0;
time_t prev_time = 0;

//Packet helpers
static uint16_t hostorder_ipv4;
static uint16_t hostorder_ipv6;

/* Hash an IPv6 address */
uint32_t ipv6_hash(const ipv6_address& ip){
	uint16_t* twos = (uint16_t*)&ip;
	return twos[0] ^ twos[1] ^ twos[2] ^ twos[3] ^ ((twos[4] ^ twos[5] ^ twos[6] ^ twos[7]) >> 16);
}

ipstat_entry** allocate_new_null_filled_page()
{
	ipstat_entry** page = (ipstat_entry**)malloc(sizeof(ipstat_entry*) * PAGES) ;
	memset(page, 0, sizeof(ipstat_entry*) * PAGES);
	return page;
}

void write_packet(struct ip_address ip, const char* packet, uint8_t length);

void handle_packet(const ipv4_header* ip, ipstat_entry* entry, uint16_t len)
{
	const char* packet = (const char*)ip;
	uint8_t len8;

	if (len > 250) {
		len = 250;
	}
	len8 = (uint8_t)len;

	ip_address ipa;
	ipa.v4 = ip->ip_dst;
	ipa.ver = 4;

	write_packet(ipa, packet, len);
}

/* Handle an IPv4 packet */
void ipv4_handler(const u_char* packet, bool incoming, uint32_t sampling_rate)
{
	const struct ipv4_header* ip;   /* packet structure         */
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	u_int32_t addr_idx;
	ipstat_entry* c;
	ipstat_entry* last = NULL;

	//IP Header
	ip = (struct ipv4_header*)(packet + sizeof(struct ether_header));
	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version != 4){
		return;
	}
	
	struct ipv4_address addr = incoming ? ip->ip_dst : ip->ip_src;

	//Get the src bucket
	addr_idx = IPV4_UINT32(addr);
	c = pages[addr_idx & 0xFFFF][addr_idx >> 16];

	while (c != NULL && (c->ip.ver != 4 || memcmp(&c->ip.v4, &addr, sizeof(addr) != 0)))
	{
		last = c;
		c = c->next;
	}
	if (c == NULL)
	{
		c = (ipstat_entry*)malloc(sizeof(ipstat_entry));
		memset(c, 0, sizeof(ipstat_entry));
		c->ip.ver = 4;
		memcpy(&c->ip.v4, &addr, sizeof(addr));
		c->isnew = true;
		if (last == NULL)
		{
			if (pages[addr_idx & 0xFFFF] == sentinel)
			{
				pages[addr_idx & 0xFFFF] = allocate_new_null_filled_page();
			}
			pages[addr_idx & 0xFFFF][addr_idx >> 16] = c;
		}
		else
		{
			last->next = c;
		}
	}

	handle_packet(ip, c, len);
	c->used = true;
}

/* Handle an IPv6 Packet */
void ipv6_handler(const u_char* packet, bool incoming, uint32_t sampling_rate)
{
}

/* Handle an ethernet packet */
uint32_t ethernet_handler(const u_char* packet, const unsigned char* mac, uint32_t sampling_rate)
{
	struct ether_header *eptr = (struct ether_header *) packet;
	
	if (memcmp(eptr->ether_dhost, mac, 6) != 0)
	{
		//Not a packet for us, or outgoing
		return 0;
	}

	if (eptr->ether_type == hostorder_ipv4)
	{
		ipv4_handler(packet, true, sampling_rate);
	}
	else if (eptr->ether_type == hostorder_ipv6)
	{
		ipv6_handler(packet, true, sampling_rate);
	}
	else
	{
		//We have no interest in non IP packets
		return 0;
	}

	return 0;
}

static uint32_t calculate_watermark(uint32_t sampling_rate) {
	if (sampling_rate < 4) {
		return SAMPLES_DEFAULT_WATERMARK;
	}
	if (sampling_rate < 32) {
		return 256;
	}
	if (sampling_rate < 128) {
		return 512;
	}
	return 1024;
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

	rc = pfring_set_poll_watermark(pd, SAMPLES_DEFAULT_WATERMARK);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while setting the watermark: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}

	rc = pfring_set_sampling_rate(pd, SAMPLES_DEFAULT_RATE);
	if (rc < 0){
		printf("#Error: A PF_RING error occured while setting sampling rate: %s rc:%d\n", strerror(errno), rc);
		return NULL;
	}

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
	u_char _buffer[95];
	u_char* buffer = _buffer;
	pfring_pkthdr hdr;
	pfring_card_settings settings;
	int epfd;
	struct epoll_event event;
	struct epoll_event events[4];
	int fd_size = 8;
	eth_def* fd_map = (eth_def*)malloc(fd_size * sizeof(eth_def));
	memset(fd_map,0,fd_size * sizeof(eth_def));
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
		
		if(sfd >= fd_size){
			fd_map = (eth_def*)realloc(fd_map, sizeof(eth_def) * (sfd + 8));
			memset(fd_map + fd_size,0,8 * sizeof(eth_def));
			fd_size = sfd + 8;
		}
		
		fd_map[sfd].ring = pd;
		fd_map[sfd].sampling_rate = SAMPLES_DEFAULT_RATE;
		get_mac(dev[i], fd_map[sfd].mac);
		
		fd_map[sfd].zc = false;
		if (pd->zc_device) {
			fd_map[sfd].zc = true;			
		}
	}

	while (running){
		int n = epoll_wait(epfd, events, 4, 500);
		if (n == 0 || (n == -1 && errno == EINTR))
		{
			for (int i=0;i<fd_size; i++)
			{
				eth_def* eth = &fd_map[i];
				if(!eth->ring) continue;
				uint32_t sampling_rate = (uint32_t)eth->sampling_rate / 10;
				if (sampling_rate == 0)
				{
					sampling_rate = 1;
				}
				int rc = pfring_set_sampling_rate(eth->ring, sampling_rate);
				if (rc < 0) {
					printf("#Error: A PF_RING error occured while setting sampling rate: %s rc:%d\n", strerror(errno), rc);
				}
				else {
					eth->sampling_rate = (uint32_t)sampling_rate;

					rc = pfring_set_poll_watermark(eth->ring, calculate_watermark(sampling_rate));
					if (rc < 0) {
						printf("#Error: A PF_RING error occured while setting watermark: %s rc:%d\n", strerror(errno), rc);
					}
				}
			}
		}
		else
		{
			for (int i = 0; i < n; i++)
			{
				eth_def* eth = &fd_map[events[i].data.fd];
				int rc = pfring_recv(eth->ring, &buffer, eth->zc ? 0 : CAPTURE_LENGTH, &hdr, 0);
				if (rc == 0)
				{
					continue;
				}
				else if (rc > 0)
				{
					uint32_t packets = ethernet_handler(buffer, eth->mac, eth->sampling_rate);
					if(packets){
						//Handling sampling rate adjustments
						int sampling_rate = (packets * eth->sampling_rate) / SAMPLES_DESIRED;
						if(sampling_rate < 1) sampling_rate = 1;
						int sampling_difference = sampling_rate - eth->sampling_rate;
						if(sampling_difference < -10 || sampling_difference > 10){
							int rc = pfring_set_sampling_rate(eth->ring, sampling_rate);
							if (rc < 0){
								printf("#Error: A PF_RING error occured while setting sampling rate: %s rc:%d\n", strerror(errno), rc);
							}else{
								eth->sampling_rate = (uint32_t)sampling_rate;

								rc = pfring_set_poll_watermark(eth->ring, calculate_watermark(sampling_rate));
								if (rc < 0) {
									printf("#Error: A PF_RING error occured while setting watermark: %s rc:%d\n", strerror(errno), rc);
								}
							}

							
						}
					}
				}
				else
				{
					printf("#Error: A PF_RING error occured while recving: %s rc:%d\n", strerror(errno), rc);
					running = false;
					break;
				}
			}	
		}
	}

	for (int i=0;i<fd_size; i++)
	{
		eth_def* eth = &fd_map[i];
		if(!eth->ring) continue;
		pfring_close(eth->ring);
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