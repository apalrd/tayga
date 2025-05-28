#!/bin/sh
#Enable IP forwarding of IPv6 only
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Bring up tun interface w/ tayga
tayga -c siit-er-node.conf --mktun

# Bring up interface
ip link set dev siit up
# Add IPv4 default route to the world
ip route add default dev siit
# Add global IPv4 address 
ip addr add 192.51.0.27/32 dev siit
# Add route to Tayga's v6 address, and the node's v4-translated address
ip route add 2001:db8:beef::1679/128 dev siit
ip route add 2001:db8:beef::ff92/128 dev siit

# You may be interested in using Proxy ND for these two addresses
# Alternatively you can route via a dynamic routing protocol
echo 1 > /proc/sys/net/ipv6/conf/eth0/proxy_ndp
ip neigh add proxy 2001:db8:beef::1679 dev eth0
ip neigh add proxy 2001:db8:beef::ff92 dev eth0

# Start Tayga
tayga -c siit-er-node.conf 