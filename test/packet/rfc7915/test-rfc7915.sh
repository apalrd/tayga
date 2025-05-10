#!/bin/sh
# Test script for RFC 7915
# This script executes the packet tests in Packetdrill

. test/report.sh

# Setup test environment
. test/setup.sh

# Set packetdrill defines
PKT_DEFINES="--debug"
PKT_DEFINES="$PKT_DEFINES --ip_version=ipv4-xlate-ipv6"
PKT_DEFINES="$PKT_DEFINES --pref64=3fff:6464::/96"
# Run packetdrill tests
packetdrill $PKT_DEFINES test/packet/rfc7915/tcp-estab.pkt  || fail


# Cleanup test environment
. test/cleanup.sh
# Report test results
report
# End of script