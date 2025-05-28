#!/bin/sh
#Enable IP forwarding of IPv4 and IPv6
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Masquerade using ip6tables
# This is certainly not the best way to configure netfilter
# For example purposes only
# for each public IP (256 hosts = 2 hex digits)
for pub in $(seq 0 255)
do
    # for each host within this public IP (16 hosts = 1 hex digit)
    for sub in $(seq 0 15)
    do
        echo Configuring client pub $pub sub $sub
        # Build client's IPv6 prefix out of their public IP suffix (2 hex digit) + sub-id (1 hex digit)
        echo IPv6 range is $(printf '2001:db8:1%02x%01x::/48' $pub $sub)
        # Internal translation range is just the public IP in hex
        echo Translation range is $(printf 'fd64::%x' $pub)
        # Port range is 4000 ports starting at 1024
        echo Port range is $(printf '%d:%d' $((1024+4000*$sub)) $((5023+4000*$sub)))
        # Using SNAT with fixed port ranges we must specify a rule for each protocol (so it will not pass non-tcp/udp/sctp)
        ip6tables -t nat -A POSTROUTING -s $(printf '2001:db8:1%02x%01x::/48' $pub $sub) -p tcp -o nat64 -j SNAT --to-source [$(printf 'fd64::%x' $pub)]:$(printf '%d-%d' $((1024+4000*$sub)) $((5023+4000*$sub)))
        ip6tables -t nat -A POSTROUTING -s $(printf '2001:db8:1%02x%01x::/48' $pub $sub) -p udp -o nat64 -j SNAT --to-source [$(printf 'fd64::%x' $pub)]:$(printf '%d-%d' $((1024+4000*$sub)) $((5023+4000*$sub)))
        ip6tables -t nat -A POSTROUTING -s $(printf '2001:db8:1%02x%01x::/48' $pub $sub) -p sctp -o nat64 -j SNAT --to-source [$(printf 'fd64::%x' $pub)]:$(printf '%d-%d' $((1024+4000*$sub)) $((5023+4000*$sub)))
        # In the case of ICMP, pass it without port numbers, although error packets will be routed by the above rules as 'related'
        ip6tables -t nat -A POSTROUTING -s $(printf '2001:db8:1%02x%01x::/48' $pub $sub) -p icmpv6 -o nat64 -j SNAT --to-source [$(printf 'fd64::%x' $pub)]
    done
done

# Bring up tun interface w/ tayga
tayga -c nat64-static.conf --mktun

# Bring up interface
ip link set dev nat64 up
# Add routes to the tun interface (distribute these via your routing protocol)
ip route add 203.0.113.0/24 dev nat64
ip route add 192.0.2.0/32 dev nat64
# Add IPv6 address (implicitly adds /64 route) (distribute this via your routing protocol)
ip addr add 2001:db8:0:6464::/64 dev nat64
# Add routes to translation network (do *not* distribute these outside of this host)
ip route add fd64::/64 dev nat64
# Add pref64 route (distribute this via your routing protocol)
ip route add 64:ff9b::/96 dev nat64

# Start Tayga
tayga -c nat64-static.conf 