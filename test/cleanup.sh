#!/bin/bash

# Teardown Tayga from a test run

## Start
echo "Stopping Tayga"

# Kill Tayga process by PID file
kill -9 $(cat /var/run/tayga.pid)
# Remove the PID file
rm -f /var/run/tayga.pid || true
# Remove the interface
ip link del dev nat64
# Remove the dummy interface
ip link del dev dummy0
# Tcpdump will quit when nat64 is deleted
