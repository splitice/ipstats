#!/bin/bash
#Usage: ipstats eth1 | bash contrib/zabbix_formatter.sh SERVER | zabbix_sender -c /etc/zabbix/zabbix_agentd.conf -i -

HOST="$1"
EXIT=0

function get_data_line {
	echo "$1" | awk '{print "'$HOST' net.ipstat[\""$1"\",\""$2"\",\"'$2'\"] "$'$3'}' | cat
	EXIT=$?
}

while read line; do
	run=1
	while [[ $run != 0 ]]; do
		if [[ "${line:0:1}" != "#" ]]; then
			get_data_line "$line" "tcp_packets" 3
			get_data_line "$line" "tcp_bytes" 4

			get_data_line "$line" "udp_packets" 5
			get_data_line "$line" "udp_bytes" 6

			get_data_line "$line" "gre_packets" 7
			get_data_line "$line" "gre_bytes" 8

			get_data_line "$line" "ipip_packets" 9
			get_data_line "$line" "ipip_bytes" 10

			get_data_line "$line" "icmp_packets" 11
			get_data_line "$line" "icmp_bytes" 12

			get_data_line "$line" "ipsec_packets" 13
			get_data_line "$line" "ipsec_bytes" 14

			get_data_line "$line" "other_packets" 15
			get_data_line "$line" "other_bytes"  16
		fi
		if [[ $EXIT != 0 ]]; then
			run=0
		else
			read line
			s=$?
			if [[ $s != 0 ]]; then
				run=0
			fi
		fi
	done | /usr/bin/zabbix_sender -c /etc/zabbix/zabbix_agentd.conf -vv -i -
done