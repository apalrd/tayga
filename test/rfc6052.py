from test_env import test_env, send_and_check
from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.all import IP, ICMP
import time


# Create an instance of TestEnv and call setup()
test = test_env("test/rfc6052")
# Enable logging for now
test.debug = True
test.TcpdumpFile = "test/rfc6052.pcap"
test.setup()

#############################################
# Variable Prefix Length (RFC 6052 2.2)
#############################################

## For each test, validate 4->6 and 6->4

# /32

# /40

# /48

# /56

# /64

# /96

#############################################
# Well Known Prefix Restricted (RFC 6042 3.1)
#############################################

# RFC1918 Class A

# RFC1918 Class B

# RFC1918 Class C

# Zero

# IPv4 Loopback

# IPv4 Link Local

# TEST-NET-1

# TEST-NET-2

# TEST-NET-3

# IPv4 Benchmarking Space

# 6to4 relay (RFC3068)

# Multicast (Class D)

# Class E

#############################################
# Local Use Well Known Prefix (RFC 6042 3.1)
#############################################

# RFC1918 Class A

# RFC1918 Class B

# RFC1918 Class C

# Zero

# IPv4 Loopback

# IPv4 Link Local

# TEST-NET-1

# TEST-NET-2

# TEST-NET-3

# IPv4 Benchmarking Space

# 6to4 relay (RFC3068)

# Multicast (Class D)

# Class E

test.report()
test.cleanup()