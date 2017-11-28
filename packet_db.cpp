#include "ip_address.h"
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#define PACKETDB_BYTES 192
#define PACKETDB_OVERHEAD 1
#define PACKETDB_OFFSET 40
#define PACKETDB_PERFILE 8192
#define PACKETDB_FILES 16

struct cmp_ip
{
	bool operator()(const struct ip_address& a, const struct ip_address& b) const
	{
		if (a.ver != b.ver) {
			return false;
		}
		return memcmp(&a, &b, sizeof(a)) < 0;
	}
};

struct fd_data {
	int fd;
	uint16_t record;
};

static std::map<struct ip_address, struct fd_data*, struct cmp_ip> files;

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

static char* get_filename(struct ip_address ip) {
	char filename_buffer[1024];
	snprintf(filename_buffer, sizeof(filename_buffer), "/opt/packetdb/%s.db", ip_to_string(ip));

	return strdup(filename_buffer);
}

static void rotate_dbfile(struct ip_address ip) {
	char* filename = get_filename(ip);
	rotate_dbfile(filename);
	free(filename);
}

static void open_dbfile(struct ip_address ip) {
	char* filename = get_filename(ip);
	int fd = open(filename, O_APPEND | O_CREAT | O_WRONLY);
	assert(fd >= 0);
	files[ip] = fd;
	free(filename);
}

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

void write_packet(struct ip_address ip, const char* packet, uint8_t length) {
	char zero_buffer[PACKETDB_BYTES];
	int res;
	auto it = files.find(ip);
	if (it == files.end()) {
		open_dbfile(ip);
		it = files.find(ip);
	}
	auto fd_data = it->second;
	if (fd_data->record++ == PACKETDB_PERFILE) {
		rotate_dbfile(ip);
		close(fd_data->fd);
		open_dbfile(ip);
		it = files.find(ip);
		fd_data = it->second;
		fd_data->record = 1;
	}

	if (length >= PACKETDB_BYTES)
	{
		length = PACKETDB_BYTES;
		write(fd_data->fd, &length, 1);
		write(fd_data->fd, packet, PACKETDB_BYTES);
	}
	else 
	{
		res = fullwrite(fd_data->fd, (const char*)&length, 1);
		res = fullwrite(fd_data->fd, packet, length);
		length = PACKETDB_BYTES - length;
		memset(zero_buffer, 0, length);
		write(fd_data->fd, zero_buffer, length);
	}
}