#include <stdio.h>
#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <string.h>
#define sprintf_s snprintf
#endif
#include "ip_address.h"

static char ip_address[46];
const char* ip_to_string(const struct ip_address addr){
	ip_to_string(addr, ip_address, sizeof(ip_address));
	return ip_address;
}
const char* ip_to_string(const struct ipv4_address addr) {
	ip_to_string(addr, ip_address, sizeof(ip_address));
	return ip_address;
}
const char* ip_to_string(const struct ipv6_address addr) {
	ip_to_string(addr, ip_address, sizeof(ip_address));
	return ip_address;
}

void ip_to_string(const struct ipv4_address addr, char* output, int length) {
	sprintf_s(output, length, "%d.%d.%d.%d", addr.byte1, addr.byte2, addr.byte3, addr.byte4);
}
void ip_to_string(const struct ipv6_address addr, char* output, int length) {
	sprintf_s(output, length, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		addr.byte1, addr.byte2, addr.byte3, addr.byte4, addr.byte5, addr.byte6, addr.byte7, addr.byte8,
		addr.byte9, addr.byte10, addr.byte11, addr.byte12, addr.byte13, addr.byte14, addr.byte15, addr.byte16);
}

void ip_to_string(const struct ip_address addr, char* output, int length){
	if (addr.ver == 4){
		ip_to_string(addr.v4, output, length);
	}
	else if (addr.ver == 6){
		ip_to_string(addr.v6, output, length);
	}
	else{
		sprintf_s(output, length, "Unknown IP Version");
	}
}

bool string_to_ip(const char* addr, struct ip_address* output){
	if (inet_pton(AF_INET, addr, &(output->v4))){
		output->ver = 4;
	}
	else if (inet_pton(AF_INET6, addr, &(output->v6))){
		output->ver = 6;
	}
	else{
		return false;
	}
	return true;
}

struct ip_address string_to_ip(const char* addr){
	struct ip_address ret;
	string_to_ip(addr, &ret);
	return ret;
}

bool sockaddr_to_ip(struct sockaddr * addr, struct ip_address* output){
	memset(output, 0, sizeof(struct ip_address));
	if (addr->sa_family == AF_INET){
		output->ver = 4;
		memcpy(&output->v4, &((struct sockaddr_in*)addr)->sin_addr, sizeof(output->v4));
	}
	else if (addr->sa_family == AF_INET6){
		output->ver = 6;
		memcpy(&output->v6, &((struct sockaddr_in6*)addr)->sin6_addr, sizeof(output->v6));
	}
	else{
		return false;
	}
	return true;
}