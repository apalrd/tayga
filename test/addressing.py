#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/addressing.py - IPv6 Addressing Tests
#   ref. RFC 6052, RFC 8125
#

from test_env import (
    test_env, 
    send_and_check, 
    send_and_none,
    test_result,
    router
)
from random import randbytes
from scapy.all import IP, UDP, IPv6, Raw
import time

# Create an instance of TestEnv
test = test_env("test/addressing")


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
    res.compare("Length",pkt[IP].len,expect_len)
    res.compare("Proto",pkt[IP].proto,expect_proto)
    res.compare("Src",pkt[IP].src,str(expect_sa))
    res.compare("Dest",pkt[IP].dst,str(expect_da))
    res.compare("Payload",pkt[Raw].load,expect_data)
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
    res.compare("Length",pkt[IPv6].plen,expect_len)
    res.compare("Proto",pkt[IPv6].nh,expect_proto)
    res.compare("Src",pkt[IPv6].src,str(expect_sa))
    res.compare("Dest",pkt[IPv6].dst,str(expect_da))
    res.compare("Payload",pkt[Raw].load,expect_data)
    return res

#############################################
# Variable Prefix Length (RFC 6052 2.2)
#############################################
def sec_2_2():
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
# Well Known Prefix Restricted (RFC 6042 3.1) w/ WKPF-Strict
#############################################
def sec_3_1_strict():
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data

    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.wkpf_strict = True
    test.tayga_conf.prefix = "64:ff9b::/96"
    test.tayga_conf.ipv6_addr = "3fff:6464::1"
    test.reload()

    # We will need to route 64:ff9b individually
    rtpref = router("64:ff9b::/96")
    pref= "64:ff9b::"

    # RFC1918 Class A
    rtpref.apply()
    send_pkt = IPv6(dst=str(test.xlate("10.1.3.4",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "RFC1918 Class A v6->v4")

    # RFC1918 Class B
    send_pkt = IPv6(dst=str(test.xlate("172.18.6.7",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt,"RFC1918 Class B v6->v4")

    # RFC1918 Class C
    send_pkt = IPv6(dst=str(test.xlate("192.168.22.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "RFC1918 Class C v6->v4")

    # TEST-NET-1
    send_pkt = IPv6(dst=str(test.xlate("192.0.2.6",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "TEST-NET-1 v6->v4")

    # TEST-NET-2
    send_pkt = IPv6(dst=str(test.xlate("198.51.100.10",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "TEST-NET-2 v6->v4")

    # TEST-NET-3
    send_pkt = IPv6(dst=str(test.xlate("203.0.113.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "TEST-NET-3 v6->v4")

    # IPv4 Benchmarking Space
    send_pkt = IPv6(dst=str(test.xlate("198.18.0.20",pref)),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
    send_and_none(test,send_pkt, "Benchmarking Space v6->v4")

    
    # DSLite space (should still work)
    expect_da = "192.0.0.2"
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(test.xlate("192.0.0.2",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "DSLite Space v6->v4")

    # 6to4 relay (RFC3068) (should also still work)
    expect_da = "192.88.99.52"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.88.99.52",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "6to4 Relay Space v6->v4")

    # It was easier to write the tests in this order
    # It saves setting a ton of sa/da's each time
    rtpref.remove()
    
    # RFC1918 Class A
    send_pkt = IP(dst=str("10.1.2.3"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("10.0.0.0/8")
    rt.apply()
    send_and_none(test,send_pkt, "RFC1918 Class A v4->v6")
    rt.remove()

    # RFC1918 Class B
    send_pkt = IP(dst=str("172.22.6.9"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("172.16.0.0/12")
    rt.apply()
    send_and_none(test,send_pkt, "RFC1918 Class B v4->v6")
    rt.remove()
 
    # RFC1918 Class C
    send_pkt = IP(dst=str("192.168.22.66"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("192.168.22.0/24")
    rt.apply()
    send_and_none(test,send_pkt, "RFC1918 Class C v4->v6")
    rt.remove()
    
    # TEST-NET-1
    send_pkt = IP(dst=str("192.0.2.7"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("192.0.2.0/24")
    rt.apply()
    send_and_none(test,send_pkt, "TEST-NET-1 v4->v6")
    rt.remove()
    
    # TEST-NET-2
    send_pkt = IP(dst=str("198.51.100.11"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("198.51.100.0/24")
    rt.apply()
    send_and_none(test,send_pkt, "TEST-NET-2 v4->v6")
    rt.remove()
    
    # TEST-NET-3
    send_pkt = IP(dst=str("203.0.113.68"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("203.0.113.0/24")
    rt.apply()
    send_and_none(test,send_pkt, "TEST-NET-3 v4->v6")
    rt.remove()

    # IPv4 Benchmarking Space
    send_pkt = IP(dst=str("198.18.0.26"),src=str(test.public_ipv6_xlate),proto=16) / Raw(randbytes(128))
    rt = router("198.18.0.0/15")
    rt.apply()
    send_and_none(test,send_pkt, "Benchmarking Space v4->v6")
    rt.remove()

    # DSLite space
    expect_da = "64:ff9b::c000:1"
    expect_sa = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str("192.0.0.1"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.0.0.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "DSLite Space v4->v6")
    rt.remove()

    # 6to4 relay (RFC3068)
    expect_da = "64:ff9b::c058:6338"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.88.99.56"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.88.99.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "6to4 Relay Space v4->v6")
    rt.remove()


    # 6to4 relay (RFC3068)
    test.section("Well Known Prefix Restricted (RFC 6042 3.1) w/ WKPF-Strict")


#############################################
# Well Known Prefix Restricted (RFC 6042 3.1) w/o WKPF-Strict
#############################################
def sec_3_1_not_strict():
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data

    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.wkpf_strict = False
    test.tayga_conf.prefix = "64:ff9b::/96"
    test.reload()

    # We will need to route 64:ff9b individually
    rtpref = router("64:ff9b::/96")
    pref= "64:ff9b::"

    # RFC1918 Class A
    expect_sa = test.public_ipv6_xlate
    expect_da = "10.1.3.4"
    expect_data = randbytes(128)
    expect_len = 128+20
    rtpref.apply()
    send_pkt = IPv6(dst=str(test.xlate("10.1.3.4",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class A v6->v4")

    # RFC1918 Class B
    expect_da = "172.18.6.7"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("172.18.6.7",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class B v6->v4")

    # RFC1918 Class C
    expect_da = "192.168.22.69"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.168.22.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class C v6->v4")

    # TEST-NET-1
    expect_da = "192.0.2.6"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.0.2.6",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-1 v6->v4")

    # TEST-NET-2
    expect_da = "198.51.100.10"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("198.51.100.10",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-2 v6->v4")

    # TEST-NET-3
    expect_da = "203.0.113.69"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("203.0.113.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-3 v6->v4")

    # IPv4 Benchmarking Space
    expect_da = "198.18.0.20"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("198.18.0.20",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "Benchmarking Space v6->v4")

    
    # DSLite space
    expect_da = "192.0.0.2"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.0.0.2",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "DSLite Space v6->v4")

    # 6to4 relay (RFC3068)
    expect_da = "192.88.99.52"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.88.99.52",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "6to4 Relay Space v6->v4")

    # It was easier to write the tests in this order
    # It saves setting a ton of sa/da's each time
    rtpref.remove()
    
    # RFC1918 Class A
    expect_sa = test.public_ipv6
    expect_da = "64:ff9b::a01:203"
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str("10.1.2.3"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("10.0.0.0/8")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class A v4->v6")
    rt.remove()

    # RFC1918 Class B
    expect_da = "64:ff9b::ac16:609"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("172.22.6.9"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("172.16.0.0/12")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class B v4->v6")
    rt.remove()
 
    # RFC1918 Class C
    expect_da = "64:ff9b::c0a8:1642"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.168.22.66"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.168.22.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class C v4->v6")
    rt.remove()
    
    # TEST-NET-1
    expect_da = "64:ff9b::c000:207"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.0.2.7"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.0.2.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-1 v4->v6")
    rt.remove()
    
    # TEST-NET-2
    expect_da = "64:ff9b::c633:640b"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("198.51.100.11"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("198.51.100.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-2 v4->v6")
    rt.remove()
    
    # TEST-NET-3
    expect_da = "64:ff9b::cb00:7144"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("203.0.113.68"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("203.0.113.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-3 v4->v6")
    rt.remove()

    # IPv4 Benchmarking Space
    expect_da = "64:ff9b::c612:1a"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("198.18.0.26"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("198.18.0.0/15")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "Benchmarking Space v4->v6")
    rt.remove()

    # DSLite space
    expect_da = "64:ff9b::c000:1"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.0.0.1"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.0.0.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "DSLite Space v4->v6")
    rt.remove()

    # 6to4 relay (RFC3068)
    expect_da = "64:ff9b::c058:6338"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.88.99.56"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.88.99.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "6to4 Relay Space v4->v6")
    rt.remove()

 
    test.section("Well Known Prefix Restricted (RFC 6042 3.1) w/o WKPF-Strict")


#############################################
# Local Use Well Known Prefix (RFC 6052 Sec 3.1 + RFC 8215)
#############################################
def sec_3_1_rfc8215():
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data

    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.wkpf_strict = True
    test.tayga_conf.prefix = "64:ff9b:1::/96"
    test.reload()

    # We will need to route 64:ff9b individually
    rtpref = router("64:ff9b:1::/96")
    pref= "64:ff9b:1::"

    # RFC1918 Class A
    expect_sa = test.public_ipv6_xlate
    expect_da = "10.1.3.4"
    expect_data = randbytes(128)
    expect_len = 128+20
    rtpref.apply()
    send_pkt = IPv6(dst=str(test.xlate("10.1.3.4",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class A v6->v4")

    # RFC1918 Class B
    expect_da = "172.18.6.7"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("172.18.6.7",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class B v6->v4")

    # RFC1918 Class C
    expect_da = "192.168.22.69"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.168.22.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "RFC1918 Class C v6->v4")

    # TEST-NET-1
    expect_da = "192.0.2.6"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.0.2.6",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-1 v6->v4")

    # TEST-NET-2
    expect_da = "198.51.100.10"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("198.51.100.10",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-2 v6->v4")

    # TEST-NET-3
    expect_da = "203.0.113.69"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("203.0.113.69",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "TEST-NET-3 v6->v4")

    # IPv4 Benchmarking Space
    expect_da = "198.18.0.20"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("198.18.0.20",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "Benchmarking Space v6->v4")

    
    # DSLite space
    expect_da = "192.0.0.2"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.0.0.2",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "DSLite Space v6->v4")

    # 6to4 relay (RFC3068)
    expect_da = "192.88.99.52"
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str(test.xlate("192.88.99.52",pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    send_and_check(test,send_pkt,ip_val, "6to4 Relay Space v6->v4")

    # It was easier to write the tests in this order
    # It saves setting a ton of sa/da's each time
    rtpref.remove()
    
    # RFC1918 Class A
    expect_sa = test.public_ipv6
    expect_da = "64:ff9b:1::a01:203"
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str("10.1.2.3"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("10.0.0.0/8")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class A v4->v6")
    rt.remove()

    # RFC1918 Class B
    expect_da = "64:ff9b:1::ac16:609"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("172.22.6.9"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("172.16.0.0/12")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class B v4->v6")
    rt.remove()
 
    # RFC1918 Class C
    expect_da = "64:ff9b:1::c0a8:1642"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.168.22.66"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.168.22.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "RFC1918 Class C v4->v6")
    rt.remove()
    
    # TEST-NET-1
    expect_da = "64:ff9b:1::c000:207"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.0.2.7"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.0.2.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-1 v4->v6")
    rt.remove()
    
    # TEST-NET-2
    expect_da = "64:ff9b:1::c633:640b"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("198.51.100.11"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("198.51.100.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-2 v4->v6")
    rt.remove()
    
    # TEST-NET-3
    expect_da = "64:ff9b:1::cb00:7144"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("203.0.113.68"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("203.0.113.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "TEST-NET-3 v4->v6")
    rt.remove()

    # IPv4 Benchmarking Space
    expect_da = "64:ff9b:1::c612:1a"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("198.18.0.26"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("198.18.0.0/15")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "Benchmarking Space v4->v6")
    rt.remove()

    # DSLite space
    expect_da = "64:ff9b:1::c000:1"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.0.0.1"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.0.0.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "DSLite Space v4->v6")
    rt.remove()

    # 6to4 relay (RFC3068)
    expect_da = "64:ff9b:1::c058:6338"
    expect_data = randbytes(128)
    send_pkt = IP(dst=str("192.88.99.56"),src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    rt = router("192.88.99.0/24")
    rt.apply()
    send_and_check(test,send_pkt,ip6_val, "6to4 Relay Space v4->v6")
    rt.remove()

    test.section("Local-Use Well Known Prefix (RFC 8215)")

#############################################
# Invalid / Out of Scope Addresses (RFC 6052 5.1)
#############################################
def sec_5_1():
    # Setup config for this section
    test.tayga_conf.default()
    test.reload()
    # Zero network
    test.debug = True
    send_pkt = IPv6(dst=test.xlate("0.0.0.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Zero Net")
    send_pkt = IPv6(dst=test.xlate("0.0.1.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Zero Net (higher)")
    send_pkt = IPv6(dst=test.xlate("0.1.1.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Zero Net (sky high)")

    # IPv4 Link Local
    send_pkt = IPv6(dst=test.xlate("169.254.0.42"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Link Local")
    send_pkt = IPv6(dst=test.xlate("169.254.69.42"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Link Local (higher)")

    # IPv4 Loopback
    send_pkt = IPv6(dst=test.xlate("127.0.0.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Loopback")
    send_pkt = IPv6(dst=test.xlate("127.0.1.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Loopback (higher)")
    send_pkt = IPv6(dst=test.xlate("127.1.1.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Loopback (sky high)")

    # IPV4 Multicast
    send_pkt = IPv6(dst=test.xlate("224.0.0.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Local Multicast")
    send_pkt = IPv6(dst=test.xlate("239.0.0.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Global Multicast")

    # IPv4 Class E
    send_pkt = IPv6(dst=test.xlate("240.0.0.1"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Class E")
    
    # Local Broadcast
    send_pkt = IPv6(dst=test.xlate("255.255.255.255"),src=str(test.public_ipv6)) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_none(test,send_pkt,"Local Broadcast")

    test.section("Invalid / Out of Scope Addresses (RFC 6052 5.1)")

# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_log_file = "test/addressing.log"
test.tayga_bin = "./tayga-cov"
test.pcap_file = "test/addressing.pcap"
#test.pcap_test_env = True
test.setup()

# Call all tests
sec_2_2()
sec_3_1_strict()
sec_3_1_not_strict()
sec_3_1_rfc8215()
sec_5_1()

test.cleanup()
#Print test report
test.report()

