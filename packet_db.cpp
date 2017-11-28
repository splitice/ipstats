#include "ip_address.h"
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include "packet_db.h"

#define PACKETDB_BYTES 192
#define PACKETDB_OVERHEAD 1
#define PACKETDB_OFFSET 40
#define PACKETDB_PERFILE 8192
#define PACKETDB_FILES 16

static bool file_exists(const char* filename) {
	return (access(filename, F_OK) != -1);
}

static void rotate_dbfile(const char* filename) {
	char filename_buffer[1024];
	char filename_buffer2[1024];

	for (int i = 0; i <= PACKETDB_FILES; i++) {
		snprintf(filename_buffer, sizeof(filename_buffer), "%s.%d", i);
		if (!file_exists(filename_buffer)) break;
		if (i == PACKETDB_FILES) {
			unlink(filename_buffer);
		}
		else {
			snprintf(filename_buffer2, sizeof(filename_buffer2), "%s.%d", i + 1);
			rename(filename_buffer, filename_buffer2);
		}
	}
	snprintf(filename_buffer, sizeof(filename_buffer), "%s.1", filename);
	rename(filename, filename_buffer);
}

template<class TIp>
static char* get_filename(TIp ip) {
	char filename_buffer[1024];
	snprintf(filename_buffer, sizeof(filename_buffer), "/opt/packetdb/%s.db", ip_to_string(ip));

	return strdup(filename_buffer);
}

template<class TIp>
static void rotate_dbfile_ip(TIp ip) {
	char* filename = get_filename(ip);
	rotate_dbfile(filename);
	free(filename);
}

template<class TIp>
void packetdb_open_dbfile(TIp ip, struct packetdb_data* data) {
	char* filename = get_filename(ip);
	int fd = open(filename, O_APPEND | O_CREAT | O_WRONLY);
	assert(fd >= 0);
	data->fd = fd;
	data->record = 0;
	free(filename);
}
template void packetdb_open_dbfile<struct ipv4_address>(struct ipv4_address ip, struct packetdb_data* data);
template void packetdb_open_dbfile<struct ipv6_address>(struct ipv6_address ip, struct packetdb_data* data);

int fullwrite(int fd, const char* data, int length) {
	int res;
	int remaining = length;
	do {
		res = write(fd, data, remaining);
		if (res == -1) {
			return res;
		}
		data += res;
		remaining -= length;
	} while (remaining != 0);
	return length;
}

template<class TIp>
void packetdb_write_packet(TIp ip, struct packetdb_data* data, const char* packet, uint8_t length) {
	char zero_buffer[PACKETDB_BYTES];
	int res;
	if (data->record++ == PACKETDB_PERFILE) {
		rotate_dbfile_ip(ip);
		close(data->fd);
		packetdb_open_dbfile(ip, data);
	}

	if (length >= PACKETDB_BYTES)
	{
		length = PACKETDB_BYTES;
		write(data->fd, &length, 1);
		write(data->fd, packet, PACKETDB_BYTES);
	}
	else 
	{
		res = fullwrite(data->fd, (const char*)&length, 1);
		res = fullwrite(data->fd, packet, length);
		length = PACKETDB_BYTES - length;
		memset(zero_buffer, 0, length);
		write(data->fd, zero_buffer, length);
	}
}

template void packetdb_write_packet<struct ipv4_address>(struct ipv4_address ip, struct packetdb_data* data, const char* packet, uint8_t length);
template void packetdb_write_packet<struct ipv6_address>(struct ipv6_address ip, struct packetdb_data* data, const char* packet, uint8_t length);