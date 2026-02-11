#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/segment.py - Test of segmentation / queue related behaviors
#
from test_env import (
    test_env,
    test_result,
    route_dest,
    router
)
from random import randbytes
from scapy.all import IP, UDP, IPv6, Raw
import time
import ipaddress
import socket
import threading
import os

# Create an instance of TestEnv
test = test_env("test/segment")

####
#  Generic IPv4 Validator
#  This test only compares IP header fields,
#  not any subsequent headers.
#  Those are checked in a different test
####
expect_sa = test.public_ipv6_xlate
expect_da = test.public_ipv4
expect_len = -1
expect_proto = 16
expect_data = None
def ip_val(pkt):
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
# Checksum Testing
#############################################
def csum():
    global expect_proto
    global expect_sa
    global expect_da
    #Create UDP socket to send packets
    sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock4.bind((str(test.test_sys_ipv4), 0))

    #Create IPv6 socket to send packets
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock6.bind((str(test.test_sys_ipv6), 0))

    #Send v4 -> v6
    expect_proto = 17
    expect_sa = test.test_sys_ipv4_xlate
    expect_da = test.public_ipv6
    #not sure why this test is so broken
    #sock4.sendto(randbytes(32), (str(test.public_ipv6_xlate), 69))
    #test.send_and_check(None,ip6_val,"V4 to V6")

    #Send v6 -> v4
    expect_sa = test.test_sys_ipv6_xlate
    expect_da = test.public_ipv4
    sock6.sendto(randbytes(32), (str(test.public_ipv4_xlate), 69))
    test.send_and_check(None,ip_val,"V6 to V4")

    #Close sockets
    sock4.close()
    sock6.close()
    test.section("Checksum Offload")

#############################################
# Multi-Queue Testing
#############################################
def multiqueue():
    global expect_da
    global expect_sa
    global expect_data
    global expect_len
    global expect_proto

    #Send a wide variety of packets which will hash differently, stimulating multi-queue
    for workers in [0, 1, 4, 8, 64]:
        # Generate test config for this one
        test.tayga_conf.default()
        test.tayga_conf.dynamic_pool = None
        test.tayga_conf.workers = workers
        test.tayga_conf.map.append("172.16.1.0/24 2001:db8:2::/120")
        test.reload()
        test_pre_nm = str(workers)+" workers "

        #Now run 128 packets with different parameters in each direction
        for i in range(128):
            #v4 to v6
            test_nm = test_pre_nm + "["+str(i)+"]"
            expect_proto = 16
            expect_da = test.public_ipv6
            expect_sa = test.public_ipv4_xlate+i
            expect_data = randbytes(128)
            expect_len = 128
            send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4+i),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" v4->v6")

            #v6 to v4
            expect_da = test.public_ipv4
            expect_sa = ipaddress.ip_address("172.16.1.0")+i
            expect_data = randbytes(128)
            expect_len = 128+20
            send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(ipaddress.ip_address("2001:db8:2::")+i),nh=16,fl=i) / Raw(expect_data)
            test.send_and_check(send_pkt,ip_val, test_nm+" v6->v4")

    #Close section
    test.section("Multi-Queue")

# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.setup()

# Call all tests
csum()
multiqueue()

time.sleep(1)
test.cleanup()
#Print test report
test.report(1281,0)