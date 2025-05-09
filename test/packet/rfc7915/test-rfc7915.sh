#!/bin/sh
# Test script for RFC 7915
# This script executes the packet tests in Packetdrill

. test/report.sh

# Setup test environment
. test/setup.sh

# Set packetdrill defines
PKT_DEFINES="--debug"
PKT_DEFINES="$PKT_DEFINES --define TAYGA_ADDR6=$TAYGA_ADDR6"
PKT_DEFINES="$PKT_DEFINES --define TAYGA_POOL4=$TAYGA_POOL4"
PKT_DEFINES="$PKT_DEFINES --define TAYGA_PREFIX=$TAYGA_PREFIX"
PKT_DEFINES="$PKT_DEFINES --define PUBLIC_IPV4=$PUBLIC_IPV4"
PKT_DEFINES="$PKT_DEFINES --define PUBLIC_IPV6=$PUBLIC_IPV6"
PKT_DEFINES="$PKT_DEFINES --define TEST_SYSTEM_IPV4=$TEST_SYSTEM_IPV4"
PKT_DEFINES="$PKT_DEFINES --define TEST_SYSTEM_IPV6=$TEST_SYSTEM_IPV6"

# Run packetdrill tests
packetdrill $PKT_DEFINES test/packet/rfc7915/icmp6-echo.pkt || fail


# Cleanup test environment
. test/cleanup.sh
# Report test results
report
# End of script