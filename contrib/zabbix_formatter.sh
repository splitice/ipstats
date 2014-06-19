#!/bin/bash
HOST="$1"

function value_n {
        echo "$1" | awk "{print \$$2}"
}

function get_data_line {
        echo -n "$HOST "
        echo "$1" | awk "BEGIN {ORS=\" \"} {print \"net.ipstat[\\\"\"\$1\"\\\",\\\"\"\$2\"\\\",\\\"$2\\\"]\"}"
        echo $(value_n "$line" $3)
}

while read line; do
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
                get_data_line "$line" "other_bytes" 16
        fi
done