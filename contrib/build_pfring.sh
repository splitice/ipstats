OUT=$(mktemp -d)
cd "$OUT"

apt-get install build-essential libnuma-dev subversion linux-headers-$(uname -r) --force-yes -y

svn co https://svn.ntop.org/svn/ntop/trunk/PF_RING/ PF_RING

cd PF_RING/kernel
make
make install

cd "$OUT"

cd PF_RING/userland/lib
./configure
make
make install

if [[ "$OUT" == *tmp* ]]; then
	rm -f -R "$OUT"
fi
