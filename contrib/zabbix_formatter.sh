#!/bin/bash
#Usage: ipstats eth1 | bash contrib/zabbix_formatter.sh SERVER

HOST="$1"
EXIT=0

function get_data_line {
        code=""
        for ((i=2; i<${#@}; i+=2)); do
                PROPERTY="${!i}"
                let f=i+1
                VALUE="${!f}"
                code=$code'print "'$HOST' net.ipstat[\""$1"\",\""$2"\",\"'$PROPERTY'\"] "$'$VALUE';'
        done
        echo "$1" | awk '{'"$code"'}'
        EXIT=$?
}

while read line; do
	run=1
	while [[ $run != 0 ]]; do
		if [[ "${line:0:1}" != "#" ]]; then
			get_data_line "$line" "tcp_packets" 3 "tcp_bytes" 4 "udp_packets" 5 "udp_bytes" 6 "gre_packets" 7 "gre_bytes" 8 "ipip_packets" 9 "ipip_bytes" 10 "icmp_packets" 11 "icmp_bytes" 12 "ipsec_packets" 13 "ipsec_bytes" 14 "other_packets" 15 "other_bytes"  16
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