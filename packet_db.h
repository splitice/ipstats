#pragma once
#include <stdint.h>
#include "ip_address.h"

struct packetdb_data {
	int fd;
	uint16_t record;
};

void write_packet(struct ip_address ip, struct packetdb_data data, const char* packet, uint8_t length);
