#!/bin/bash
set -e

QUEUE=0

echo "Building Firewall (Enforcement Mode)..."
make 

echo
echo "Applying NFQUEUE rules (IPv4 + IPv6)..."
sudo ./scripts/flush_nfqueue.sh 2>/dev/null || true

sudo iptables  -I INPUT  -j NFQUEUE --queue-num $QUEUE --queue-bypass
sudo iptables  -I OUTPUT -j NFQUEUE --queue-num $QUEUE --queue-bypass
sudo ip6tables -I INPUT  -j NFQUEUE --queue-num $QUEUE --queue-bypass
sudo ip6tables -I OUTPUT -j NFQUEUE --queue-num $QUEUE --queue-bypass

echo
echo "Enforcement Mode Active!"
echo "Packets will now be filtered by your firewall rules."
echo "Press CTRL+C to stop."
echo

sudo ./firewall

echo
echo "Cleaning up NFQUEUE rules..."
sudo ./scripts/flush_nfqueue.sh
echo "Firewall enforcement stopped."

./scripts/clean.sh
