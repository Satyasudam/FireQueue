#!/bin/bash
set -e

echo "Building Firewall (Simulation Mode)..."
make

echo
echo "Starting Simulation Mode..."
echo "   (Packets are only monitored and logged — not blocked.)"
echo

sudo ./firewall
