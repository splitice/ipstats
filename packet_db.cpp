#include "ip_address.h"
#include <map>

#define PACKETDB_BYTES 192
#define PACKETDB_OVERHEAD 40
#define PACKETDB_OFFSET 40
#define PACKETDB_PERFILE 16384

static std::map<struct ip_address, int> files;

static void rotate_dbfile(const char* filename) {
	char filename_buffer[1024];
	char filename_buffer2[1024];

	for (int i = 0; i <= 6; i++) {
		snprintf(filename_buffer, sizeof(filename_buffer), "%s.%d", i);
		if (!file_exists(filename_buffer)) break;
		if (i == 6) {
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

static void get_filename(struct ip_address ip) {
	char filename_buffer[1024];
	snprintf(filename_buffer, sizeof(filename_buffer), "/opt/packetdb/%s.db", ip_to_string(ip));
	
	return strdup(filename_buffer);
}

static void open_dbfile(struct ip_address ip) {

}

static int get_filehandle(struct ip_address ip) {

}

void write_packet(struct ip_address ip, char* packet) {
	auto it = files.find(ip);
	if (it == files.end()) {
		open_dbfile(ip);
		it = files.find(ip);
	}
	if (lseek(it->second) == (PACKETDB_PERFILE * (PACKETDB_OVERHEAD + PACKETDB_BYTES))) {
		rotate_dbfile();
		open_dbfile(ip);
		it = files.find(ip);
	}

	write(it->second);
}