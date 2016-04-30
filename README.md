ipstats
=======

High Performance per IP address (and protocol) bandwidth statistics supporting IPv4 & IPv6 addressing.

# Example Output
```
#TIMESTAMP DIRECTION IP TCP UDP GRE IPIP ICMP IPSEC OTHER
1461988630 IN 192.249.60.42 0 0 5 240 0 0 0 0 0 0 0 0 0 0
1461988630 OUT 192.249.60.42 0 0 0 0 0 0 0 0 0 0 0 0 0 0
```

IP ```1.2.3.4``` has sent no traffic, however it has received 100 TCP packets, totalling 5552 bytes. Counters are implemented using a 32 bit unsigned integer for packets and bytes bytes.

# Usage
```ipstats [device]```

ipstats listens on a given device. ```all``` can be specified to listen to all interfaces. Multiple devices can be supplied if compile with PF_RING support.

# Installation
ipstats can be compiled using the included Makefile. PF_RING is required. A helper script to compile and install pf_ring has been included (see contrib)

# Performance
On a reasonable Xeon the CPU usage is minimal (at 30mbit). CPU As measured on a Intel(R) Atom(TM) CPU D525 @ 1.80GHz: <0.5% CPU usage at 20mbit
 
CPU Usage can be decreased by increasing the sampling rate.