#!/bin/bash
CENT="/etc/redhat-release"
OUT=$(mktemp -d)
cd "$OUT"

if [[ -z "$1" ]]; then
	kernel=$(uname -r)
else
	kernel="$1"
fi
if [ -f $CENT ]; then 
	yum install kernel-devel gcc make kernel-headers numactl-devel.x86_64 numactl.x86_64 libpcap-devel.x86_64  libpcap.x86_64 git -y
else 
	apt-get install build-essential libnuma-dev linux-headers-$kernel git --force-yes -y
fi

git clone https://github.com/ntop/PF_RING

cd PF_RING/kernel
BUILD_KERNEL=$kernel make
BUILD_KERNEL=$kernel make install

cd "$OUT"

cd PF_RING/userland/lib
./configure
make
make install

if [[ "$OUT" == *tmp* ]]; then
	rm -f -R "$OUT"
fi
