#pragma once
#include <stdint.h>
#include "ip_address.h"

struct packetdb_data {
	int fd;
	uint16_t record;
};

template<class TIp>
void packetdb_open_dbfile(TIp ip, struct packetdb_data* data);

template<class TIp>
void packetdb_write_packet(TIp ip, struct packetdb_data* data, const char* packet, uint8_t length);
