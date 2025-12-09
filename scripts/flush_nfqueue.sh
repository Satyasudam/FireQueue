#!/bin/bash

echo "Flushing NFQUEUE iptables rules..."

sudo iptables  -D INPUT  1 2>/dev/null
sudo iptables  -D OUTPUT 1 2>/dev/null
sudo ip6tables -D INPUT  1 2>/dev/null
sudo ip6tables -D OUTPUT 1 2>/dev/null

echo "NFQUEUE unhooked"

