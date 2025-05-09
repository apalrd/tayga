#!/bin/bash

# Setup test
. test/setup.sh

set -x
# Start iperf server
iperf3 -s -p 6464 -D -I /var/run/iperf.pid || exit 1
# Check if iperf started successfully
if [ ! -f /var/run/iperf.pid ]; then
    echo "iperf failed to start"
    exit 1
fi

# Run iperf from IPv6 to IPv4
iperf3 -c $TAYGA_PREFIX$TEST_SYSTEM_IPV4 -p 6464 -t 10 -B $TEST_SYSTEM_IPV6 -b 10m

# Run iperf from IPv4 to IPv6
iperf3 -c $TAYGA_PREFIX$TEST_SYSTEM_IPV4 -p 6464 -t 10 -B $TEST_SYSTEM_IPV6 -b 10m -R


# Stop iperf server
kill -9 $(cat /var/run/iperf.pid) || exit 1
# Remove the PID file
rm -f /var/run/iperf.pid || exit 1

set +x
# Cleanup test
. test/cleanup.sh