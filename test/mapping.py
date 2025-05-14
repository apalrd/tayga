#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/mapping.py - Mapping methods of v4/v6 addresses
#   ref. RFC 6052, 7757
#
from test_env import (
    test_env, 
    send_and_check, 
    send_and_none,
    test_result,
    router,
    route_dest
)
from random import randbytes
from scapy.all import IP, UDP, IPv6, Raw
import time

# Create an instance of TestEnv
test = test_env("test/mapping")


####
#  Generic IPv4 Validator
#  This test only compares IP header fields,
#  not any subsequent headers.
#  Those are checked in a different test
####
expect_sa = test.public_ipv6_xlate
expect_da = test.public_ipv4
expect_len = 0
expect_proto = 16
expect_data = None
def ip_val(pkt):
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv4",isinstance(pkt.getlayer(1),IP))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Field Comparison
    if expect_len >= 0: res.compare("Length",pkt[IP].len,expect_len)
    res.compare("Proto",pkt[IP].proto,expect_proto)
    res.compare("Src",pkt[IP].src,str(expect_sa))
    res.compare("Dest",pkt[IP].dst,str(expect_da))
    if expect_data is not None: res.compare("Payload",pkt[Raw].load,expect_data)
    return res



####
#  Generic IPv Validator
####
def ip6_val(pkt):
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv6",isinstance(pkt.getlayer(1),IPv6))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Field Comparison
    if expect_len >= 0: res.compare("Length",pkt[IPv6].plen,expect_len)
    res.compare("Proto",pkt[IPv6].nh,expect_proto)
    res.compare("Src",pkt[IPv6].src,str(expect_sa))
    res.compare("Dest",pkt[IPv6].dst,str(expect_da))
    if expect_data is not None: res.compare("Payload",pkt[Raw].load,expect_data)
    return res


#############################################
# Variable Prefix Length (RFC 6052 2.2)
# Tests RFC6052-style address encapsulation
#############################################
def rfc6052_mapping():
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data

    ## For each test, validate 4->6 and 6->4
    rt = router("3fff:6464::/32")
    rt.apply()

    # /32
    # Reconfigure Tayga:
    test.tayga_conf.default()
    test.tayga_conf.prefix = "3fff:6464::/32"
    test.reload() 
    #v6 -> v4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/32 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102::abcd"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/32 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102:ab00::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/32 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102:abcd:ef12:5678:1234"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/32 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:c0a8:102::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/32 v4->v6")


    # /40
    # Reconfigure Tayga:
    test.tayga_conf.prefix = "3fff:6464::/40"
    test.reload()
    #v6 -> v4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:0002::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/40 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:0002:abcd:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/40 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:fb02::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/40 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:cd02:1234:5678:1245"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/40 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:c0:a801:2::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/40 v4->v6")


    # /48
    # Reconfigure Tayga:
    test.tayga_conf.prefix = "3fff:6464::/48"
    test.reload()
    #v6 -> v4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:1:0200::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/48 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:1:0200:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/48 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:fa01:0200::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/48 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:6901:0200:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/48 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:0:c0a8:1:200::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/48 v4->v6")

    # /56
    # Reconfigure Tayga:
    test.tayga_conf.prefix = "3fff:6464::/56"
    test.reload()
    #v6 -> v4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:a8:102::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/56 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:a8:102:1234:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/56 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:dca8:102::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/56 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:eda8:102:4567:9817"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/56 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:0:c0:a8:102::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/56 v4->v6")

    # /64
    # Reconfigure Tayga:
    test.tayga_conf.prefix = "3fff:6464::/64"
    test.reload()
    #v6 -> v4
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str("3fff:6464::c0:a801:200:0"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/64 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::c0:a801:200:feed"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/64 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::15c0:a801:200:0"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/64 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::68c0:a801:200:face"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/64 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464::c0:a801:200:0"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/64 v4->v6")

    # /96
    #reconfigure tayga
    test.tayga_conf.default()
    test.reload()
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "/96 v6->v4")
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip6_val, "/96 v4->v6")

    # Cleanup
    rt.remove()
    test.section("Variable Prefix Length (RFC 6052 2.2)")


#############################################
# Explicit Address Mapping (RFC 7757 3.2)
#############################################
def rfc7757_eam():
    test.section("Explicit Address Mapping (RFC 7757 3.2)")

#############################################
# Dynamic Pool Mapping (not specified by RFCs)
#############################################
def dynamic_pool():
    test.section("Dynamic Pool Mapping (not specified by RFCs)")

#############################################
# No Mapping Exists
#############################################
def no_map_exists():
    test.section("No Mapping Exists")



# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_bin = "./tayga-cov"
test.setup()

# Call all tests
rfc6052_mapping()
rfc7757_eam()
dynamic_pool()
no_map_exists()

test.cleanup()
#Print test report
test.report()
