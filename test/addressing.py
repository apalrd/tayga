#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/addressing.py - V4-in-V6 Addressing Tests
#   ref. RFC 6052, RFC 8125
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
    if expect_len >= 0: res.compare("Length",pkt[IP].len,expect_len)
    res.compare("Proto",pkt[IP].proto,expect_proto)
    res.compare("Src",pkt[IP].src,str(expect_sa))
    res.compare("Dest",pkt[IP].dst,str(expect_da))
    if expect_data is not None: res.compare("Payload",pkt[Raw].load,expect_data)
    return res



####
#  Generic IPv6 Validator
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





####
#  Generic Prefix Test
#  Tests src/dest in v4/v6 directions
#  pref ix pref64 (assumed to be /96)
#  net is a single address in the network to test
####
def test_prefix(pref,net,name,expect_drop,expect_icmp):
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data
    global test

    # v6 dest is in net
    rt_us = router(pref+"/96")
    rt_us.apply()
    expect_proto = 16
    expect_sa = test.public_ipv6_xlate
    expect_da = net
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(test.xlate(net,pref)),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    if expect_drop: send_and_none(test,send_pkt, name+" v6 dest")
    elif expect_icmp:
        #Expect ICMP instead of current nh
        expect_sa = test.tayga_ipv6
        expect_da = test.public_ipv6
        expect_proto = 58
        expect_data = None
        expect_len = -1
        send_and_check(test,send_pkt,ip6_val, name+" v6 dest")
    else: 
        send_and_check(test,send_pkt,ip_val, name+" v6 dest")
    rt_us.remove()

    # v6 src is in net, dest must hit a static mapping
    # also flip the whole damn routing table around
    rt_us = router(str(test.public_ipv6_xlate),route_dest.ROUTE_TEST)
    rt_ds = router(str(test.public_ipv6))
    rt_us.apply()
    rt_ds.apply()
    expect_sa = net
    expect_da = test.public_ipv6_xlate
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=test.public_ipv6,src=str(test.xlate(net,pref)),nh=16) / Raw(expect_data)
    if expect_drop: send_and_none(test,send_pkt, name+" v6 src")
    elif expect_icmp:
        #Expect ICMP instead of current nh
        expect_sa = test.tayga_ipv6
        expect_da = str(test.xlate(net,pref))
        expect_proto = 58
        expect_data = None
        expect_len = -1
        send_and_check(test,send_pkt,ip6_val, name+" v6 src")
    else: 
        send_and_check(test,send_pkt,ip_val, name+" v6 src") 
    rt_us.remove()
    rt_ds.remove()

    # v4 dest is in net
    rt_us = router(net+"/32")
    rt_ds = router(str(test.public_ipv6_xlate),route_dest.ROUTE_TEST)
    rt_us.apply()
    rt_ds.apply()
    expect_sa = test.public_ipv6
    expect_da = str(test.xlate(net,pref))
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=net,src=str(test.public_ipv6_xlate),proto=16) / Raw(expect_data)
    if expect_drop: send_and_none(test,send_pkt, name+" v4 dest")
    elif expect_icmp:
        #Expect ICMP instead of current nh
        expect_sa = test.tayga_ipv4
        expect_da = test.public_ipv6_xlate
        expect_proto = 1
        expect_data = None
        expect_len = -1
        send_and_check(test,send_pkt,ip_val, name+" v4 dest")
    else: 
        send_and_check(test,send_pkt,ip6_val, name+" v4 dest") 
    rt_us.remove()
    rt_ds.remove()

    # v4 src is in net
    expect_sa = str(test.xlate(net,pref))
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=net,proto=16) / Raw(expect_data)
    if expect_drop: send_and_none(test,send_pkt, name+" v4 src")
    elif expect_icmp:
        #Expect ICMP instead of current nh
        expect_sa = test.tayga_ipv4
        expect_da = net
        expect_proto = 1
        expect_data = None
        expect_len = -1
        send_and_check(test,send_pkt,ip_val, name+" v4 src")
    else: 
        send_and_check(test,send_pkt,ip6_val, name+" v4 src") 



#############################################
# Public Prefix Limitations Generic Function
#############################################
def prefix_generic(pref,strict,expect_drop,expect_icmp):
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data
    global test


    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.wkpf_strict = strict
    test.tayga_conf.prefix = pref+"/96"
    test.tayga_conf.ipv6_addr = str(test.tayga_ipv6)
    test.reload()

    # Perform tests using generic test function
    test_prefix(pref,"10.1.3.4","RFC1918 Class A",expect_drop,expect_icmp)
    test_prefix(pref,"172.18.6.7","RFC1918 Class B",expect_drop,expect_icmp)
    test_prefix(pref,"192.168.22.69","RFC1918 Class C",expect_drop,expect_icmp)
    test_prefix(pref,"192.0.2.6","TEST-NET-1",expect_drop,expect_icmp)
    test_prefix(pref,"198.51.100.10","TEST-NET-2",expect_drop,expect_icmp)
    test_prefix(pref,"203.0.113.69","TEST-NET-3",expect_drop,expect_icmp)
    test_prefix(pref,"198.18.0.20","Benchmarking Space",expect_drop,expect_icmp)
    # These prefixes should not be prevented from translation
    test_prefix(pref,"192.0.0.2","DSLite Space",False,False)
    test_prefix(pref,"192.88.99.52","6to4 Relay Space",False,False)

    #Finished

#############################################
# Well Known Prefix Restricted (RFC 6042 3.1) w/ WKPF-Strict
#############################################
def wkpf_strict():
    #Use common section 3.1 function
    prefix_generic("64:ff9b::",True,False,True)
    test.section("Well Known Prefix Restricted (RFC 6042 3.1) w/ WKPF-Strict")


#############################################
# Public Prefix Limitations Generic Function
#############################################
def wkpf_not_strict():
    #Use common section 3.1 function
    prefix_generic("64:ff9b::",False,False,False)
    test.section("Well Known Prefix Restricted (RFC 6042 3.1) w/o WKPF-Strict")


#############################################
# Local Use Well Known Prefix (RFC 6052 Sec 3.1 + RFC 8215)
#############################################
def rfc8215_local_use():
    #Use common section 3.1 function
    prefix_generic("64:ff9b:1::",True,False,False)
    test.section("Local-Use Well Known Prefix (RFC 8215)")

#############################################
# Invalid / Out of Scope Addresses (RFC 6052 5.1)
#############################################
def invalid_ranges():
    # Setup config for this section
    test.tayga_conf.default()
    test.reload()
    pref = "3fff:6464::"

    # Zero network should be dropped (TBD if this is the best behavior)
    # Zero Addr also does not forward correctly in the test env
    test_prefix(pref,"0.0.0.0","Zero Addr",True,False)

    test_prefix(pref,"0.0.0.1","Zero Net Low",True,False)
    test_prefix(pref,"0.0.1.1","Zero Net Mid",True,False)
    test_prefix(pref,"0.1.1.1","Zero Net High",True,False)

    # IPv4 Link Local definitely should be dropped
    test_prefix(pref,"169.254.0.42","Link Local Low",True,False)
    test_prefix(pref,"169.254.69.42","Link Local High",True,False)

    # IPv4 Loopback absolutely must be dropped
    test_prefix(pref,"127.0.0.1","Loopback",True,False)
    test_prefix(pref,"127.0.1.1","Loopback Mid",True,False)
    test_prefix(pref,"127.1.1.1","Loopback High",True,False)

    # IPv4 Multicast also again must be dropped
    # The v4 versions of these packets do not make it through the test env either
    test_prefix(pref,"224.0.0.1","Local Multicast",True,False)
    test_prefix(pref,"239.0.0.1","Global Multicast",True,False)

    # IPv4 Class E should be allowed
    test_prefix(pref,"240.0.0.1","Class E Very Low",False,False)
    test_prefix(pref,"250.0.0.0","Class E Low",False,False)
    test_prefix(pref,"251.5.6.7","Class E Mid",False,False)
    test_prefix(pref,"255.255.255.254","Class E High",False,False)
    
    # Local Broadcast should probably be dropped
    # This one is again hard to test properly
    test_prefix(pref,"255.255.255.255","Local Broadcast",True,False)

    test.section("Invalid / Out of Scope Addresses (RFC 6052 5.1)")

# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_bin = "./tayga-cov"
test.setup()

# Call all tests
wkpf_strict()
wkpf_not_strict()
rfc8215_local_use()
invalid_ranges()

time.sleep(1)
test.cleanup()
#Print test report
test.report()

