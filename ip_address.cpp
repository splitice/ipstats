#include <stdio.h>
#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <string.h>
#define sprintf_s snprintf
#endif
#include "ip_address.h"

static char ip_address[24];
const char* ip_to_string(const struct ip_address addr){
	ip_to_string(addr, ip_address, sizeof(ip_address));
	return ip_address;
}

void ip_to_string(const struct ip_address addr, char* output, int length){
	if (addr.ver == 4){
		sprintf_s(output, length, "%d.%d.%d.%d", addr.v4.byte1, addr.v4.byte2, addr.v4.byte3, addr.v4.byte4);
	}
	else if (addr.ver == 6){
		sprintf_s(output, length, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", addr.v6.byte1, addr.v6.byte2, addr.v6.byte3, addr.v6.byte4, addr.v6.byte5, addr.v6.byte6, addr.v6.byte7, addr.v6.byte8);
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