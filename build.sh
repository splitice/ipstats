#!/bin/bash

COMPILE_OPTIONS="-lpcap"

if [[ $1 == "fring" ]]; then
	COMPILE_OPTIONS="$LIBS -lpfring -lnuma -DUSE_PF_RING"
fi

g++ ipstats.c $COMPILE_OPTIONS -O3 -o ipstats