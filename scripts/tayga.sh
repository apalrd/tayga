# This file is executed when Tayga is started
# Use it to configure your tunnel device
# This script is executed with Tayga's user/group (nobody)
# But with CAP_NET_ADMIN to allow the `ip` command to work

ip link set up dev nat64
ip addr add 192.168.255.0/24 dev nat64
ip route add 64:ff9b::/96 dev nat64
