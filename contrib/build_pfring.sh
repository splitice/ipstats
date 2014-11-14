#!/bin/bash

OUT=$(mktemp -d)
cd "$OUT"

if [[ -z "$1" ]]; then
	kernel=$(uname -r)
else
	kernel="$1"
fi

apt-get install build-essential libnuma-dev subversion linux-headers-$kernel --force-yes -y

svn co https://svn.ntop.org/svn/ntop/trunk/PF_RING/ PF_RING

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
