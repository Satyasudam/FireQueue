#!/bin/bash

echo " Cleaning build and logs..."
rm -f firewall
rm -f data/firewall.log
make clean 2>/dev/null || true

sudo ./scripts/flush_nfqueue.sh 2>/dev/null

echo " Project cleaned"

