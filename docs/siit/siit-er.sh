#!/bin/sh
#Enable IP forwarding of IPv4 and IPv6
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Bring up tun interface w/ tayga
tayga -c siit-er.conf --mktun

# Bring up interface
ip link set dev siit up
# Add IPv4 default route to the world
ip route add default dev siit
# Add route to Tayga, and the v4-translated address space
# Distribute this (or an aggregate) via your dynamic routing protocol
# OR use proxy-ND for these 8 addresses
ip route add 2001:db8:beef::420/125 dev siit
# As is tradition, we completely waste the zero and max address in IPv4
# So, take the first (usable) address for outselves on the island network
# Out of these very expensive 8 addresses, you can now use 5 of them
# and run DHCP or whatever
ip addr add 192.51.0.65/29 dev eth1 

# Start Tayga
tayga -c siit-er.conf 