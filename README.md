ipstats
=======

High Performance per IP address (and protocol) bandwidth statistics.

# Example Output
```
#DIRECTION IP TCP UDP GRE IPIP ICMP IPSEC OTHER
IN 1.2.3.4 100 5552 0 0 0 0 0 0 0 0 0 0
OUT 1.2.3.4 0 0 0 0 0 0 0 0 0 0 0 0
```

IP ```1.2.3.4``` has sent no traffic, however it has received 100 TCP packets, totalling 5552 bytes. Counters are implemented using 32 bit unsigned integers.

# Usage
```ipstats [device]```

ipstats listens on a given device. ```all``` can be specified to listen to all interfaces.

# Installation
ipstats can be compiled using the included ```build.sh```, pf_ring support can be enabled by adding using ```build.sh pf_ring```. A helper script to compile and install pf_ring has been included.

# CPU Usage.
As measured on a Intel(R) Atom(TM) CPU D525   @ 1.80GHz

**libpcap 1.0+: ***~10% CPU usage at 20mbit
**pf_ring: **<0.5% CPU usage at 20mbit