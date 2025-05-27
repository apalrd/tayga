#!/bin/sh
#Enable IP forwarding of IPv4 and IPv6
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Masquerade using iptables using the public IPv4 of eth0
iptables -t nat -A POSTROUTING -s 192.168.240.0/24 -o eth0 -j MASQUERADE

# Bring up tun interface w/ tayga
tayga -c nat64-dynpool.conf --mktun

# Bring up interface
ip link set dev nat64 up
# Add IPv4 IP (implicitly adds /20 route)
ip addr add 192.168.240.0/20 dev nat64
# Add IPv6 address (implicitly adds /64 route)
ip addr add 2001:db8:beef:6464::/64 dev nat64
# Add pref64 route (distribute this via your routing protocol))
ip route add 64:ff9b::/96 dev nat64

# Start Tayga
tayga -c nat64-dynpool.conf 