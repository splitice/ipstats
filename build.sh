#!/bin/bash

gcc -std=gnu99 ipstats.c -lpcap -O3 -o ipstats