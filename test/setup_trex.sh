#Create a new network namespace, move two interfaces into it, launch Tayga inside
ip netns add tayga_test
#enable forwarding
ip netns exec tayga_test sh -c 'echo 1 > /proc/sys/net/ipv4/conf/all/forwarding'
ip netns exec tayga_test sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
#launch tayga mktun
ip netns exec tayga_test ./tayga -c tayga.conf -d --mktun
#bring up if
ip netns exec tayga_test ip link set up dev nat64
ip netns exec tayga_test ip route add 64:ff9b::/96 dev nat64
ip netns exec tayga_test ip route add 192.168.255.0/24 dev nat64
#launch tayga
ip netns exec tayga_test ./tayga -c tayga.conf -d > tayga.log &
#add local ips
ip netns exec tayga_test ip addr add 2001:db8:6464::1/128 dev lo
ip netns exec tayga_test ip addr add 2001:db8:6464::2/128 dev lo
ip netns exec tayga_test ip addr add 2001:db8:6464::3/128 dev lo
ip netns exec tayga_test ip addr add 2001:db8:6464::4/128 dev lo
ip netns exec tayga_test ip addr add 2001:db8:6464::5/128 dev lo
ip netns exec tayga_test ip addr add 198.18.0.1/32 dev lo
ip netns exec tayga_test ip addr add 198.18.0.2/32 dev lo
ip netns exec tayga_test ip addr add 198.18.0.3/32 dev lo
ip netns exec tayga_test ip addr add 198.18.0.4/32 dev lo
ip netns exec tayga_test ip addr add 198.18.0.5/32 dev lo
sleep 1
ip netns exec tayga_test python3 test/throughput.py
#exit
ip netns del tayga_test
