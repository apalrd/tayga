#!/bin/bash

# Setup Tayga for a test run
# This script executes Tayga in the background

## Start
echo "Setting Up Tayga"

## Environment Variables
# Allow overriding tayga binary for coverage testing
TAYGA="${TAYGA:-./tayga}"
# IP Range Defaults
TAYGA_POOL4="${TAYGA_POOL4:-192.168.255.0/24}"  # Tayga pool4 range
PUBLIC_IPV4="${PUBLIC_IPV4:-203.0.113}"    # Public IP range (/24)
TEST_SYSTEM_IPV4="${TEST_SYSTEM_IPV4:-172.16.0.1}" # Test System IP
TRANSLATION_PREFIX="${TRANSLATION_PREFIX:-3fff:6464::}" # Translation prefix
PUBLIC_IPV6="${PUBLIC_IPV6:-2001:db8::}"     # Public IP range
TEST_SYSTEM_IPV6="${TEST_SYSTEM_IPV6:-2001:db8::64}" # Test System IP
# Configuration File
TAYGA_CONF="${TAYGA_CONF:-test/tayga.conf}" # Tayga configuration file


## Enable Forwarding
echo "Enabling IPv4 and IPv6 forwarding"
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

## Bring Up Interface
${TAYGA} -c ${TAYGA_CONF} -d --mktun || exit 1
# Bring up the interface
echo "Bringing up the NAT64 interface"
ip link set dev nat64 up
ip addr add ${TAYGA_POOL4} dev nat64
ip addr add ${TRANSLATION_PREFIX}/96 dev nat64

# Add System IPs to a dummy interface
echo "Creating dummy interface"
ip link add dummy0 type dummy
ip link set dummy0 up
ip addr add ${TEST_SYSTEM_IPV4}/32 dev dummy0
ip addr add ${TEST_SYSTEM_IPV6}/128 dev dummy0

# If tcpdump file variable is set, start tcpdump
if [ -n "${TCPDUMP_FILE}" ]; then
    echo "Starting tcpdump"
    #daemon --name=tcpdump --inherit -- tcpdump -i nat64 -w ${TCPDUMP_FILE}
    tcpdump -i nat64 -w ${TCPDUMP_FILE} &
    echo $! > /var/run/tcpdump.pid
fi

## Start Tayga
echo "Starting Tayga"
${TAYGA} -c ${TAYGA_CONF} -p /var/run/tayga.pid || exit 1
# Check if Tayga started successfully
if [ ! -f /var/run/tayga.pid ]; then
    echo "Tayga failed to start"
    exit 1
fi


