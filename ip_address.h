#ifndef IPADDR_H
#define IPADDR_H
#include <stdint.h>

/* IPv4 or IPv6 address */
struct ipv4_address {
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
};
struct ipv6_address {
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
	uint8_t byte5;
	uint8_t byte6;
	uint8_t byte7;
	uint8_t byte8;
	uint8_t byte9;
	uint8_t byte10;
	uint8_t byte11;
	uint8_t byte12;
	uint8_t byte13;
	uint8_t byte14;
	uint8_t byte15;
	uint8_t byte16;
};
struct ip_address
{
	union {
		struct ipv4_address v4;
		struct ipv6_address v6;
	};
	uint8_t ver;
};

const char* ip_to_string(const struct ip_address addr);
void ip_to_string(const struct ip_address addr, char* output, int length);
bool string_to_ip(const char* addr, struct ip_address* output);
struct ip_address string_to_ip(const char* addr);
bool sockaddr_to_ip(struct sockaddr * addr, struct ip_address* output);

#endif