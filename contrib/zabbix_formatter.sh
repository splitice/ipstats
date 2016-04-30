#!/bin/bash
# Usage: ipstats eth1 | bash contrib/zabbix_formatter.sh SERVER
HOST="$1"
function awk_script {
        echo -n "{"
        for ((i=1; i<${#@}; i+=2)); do
                PROPERTY="${!i}"
                let f=i+1
                VALUE="${!f}"
                echo -n 'print "'$HOST' net.ipstat[\""$2"\",\""$3"\",\"'$PROPERTY'\"] "$1" "$'$VALUE';'
        done
        echo -n '}'
}
AWK_SCRIPT=$(awk_script "tcp_packets" 4 "tcp_bytes" 5 "udp_packets" 6 "udp_bytes" 7 "gre_packets" 8 "gre_bytes" 9 "ipip_packets" 10 "ipip_bytes" 11 "icmp_packets" 12 "icmp_bytes" 13 "ipsec_packets" 14 "ipsec_bytes" 15 "other_packets" 16 "other_bytes" 17)
while read line; do
	while [[ $run != 0 ]]; do
			read line
			s=$?
			if [[ $s != 0 ]]; then
					run=0
			else
					echo "$line"
			fi
	done | grep --line-buffered -v -E '^#' | awk "$AWK_SCRIPT"  | /usr/bin/zabbix_sender -T -c /etc/zabbix/zabbix_agentd.conf -vv -i -
done