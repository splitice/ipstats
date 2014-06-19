#!/bin/bash

COMPILE_OPTIONS="-lpcap"

if [[ $1 == "pfring" ]]; then
	COMPILE_OPTIONS="$COMPILE_OPTIONS -lpfring -lnuma -lrt -DUSE_PF_RING"
fi

g++ ipstats.c $COMPILE_OPTIONS -O3 -o ipstats