#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/translate.py - IP/ICMP Packet Translation Tests
#   ref. RFC 7915 (obsoletes RFC 6145, 2765), RFC 6791
#

from test_env import (
    test_env, 
    send_and_check, 
    send_and_none,
    test_result,
)
from random import randbytes
from scapy.all import IP, ICMP, UDP, IPv6, Raw
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6Unknown,
    ICMPv6ParamProblem,
    ICMPv6TimeExceeded,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
)
import time

## Test Environment global
test = test_env("test/translate")

####
#  Generic ICMPv4 Validator
####
expect_type = 0
expect_code = 0
expect_id = -1
expect_seq = -1
expect_mtu = -1
expect_addr = test.public_ipv6_xlate
def icmp4_val(pkt):
    global expect_type
    global expect_code
    global expect_id
    global expect_seq
    global expect_mtu
    global expect_addr
    global expect_ptr
    res = test_result()
    res.check("Contains IP",pkt.haslayer(IP))
    res.check("Contains ICMP",pkt.haslayer(ICMP))
    #Bail early so we don't get derefrence errors
    if (not IP in pkt) or (not ICMP in pkt):
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IP].src,str(expect_addr))
    res.compare("Dst IP",pkt[IP].dst,str(test.public_ipv4))
    res.compare("Type",pkt[ICMP].type,expect_type)
    res.compare("Code",pkt[ICMP].code,expect_code)
    if expect_id >= 0:
        res.compare("ID",pkt[ICMP].id,expect_id)
    if expect_seq >= 0:
        res.compare("Seq",pkt[ICMP].seq,expect_seq)
    if expect_mtu >= 0:
        res.compare("MTU",pkt[ICMP].nexthopmtu,expect_mtu)
    if expect_ptr >= 0:
        res.compare("PTR",pkt[ICMP].ptr,expect_ptr)
    return res

####
#  Generic ICMPv6 Validator
####
expect_class = None
expect_ptr = -1
def icmp6_val(pkt):
    global expect_code
    global expect_type
    global expect_addr
    global expect_class
    global expect_ptr
    global expect_mtu
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv6",isinstance(pkt.getlayer(1),IPv6))
    res.compare("Expected Class",type(pkt.getlayer(2)),type(expect_class))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IPv6].src,str(expect_addr))
    res.compare("Dst IP",pkt[IPv6].dst,str(test.public_ipv6))
    res.compare("Type",pkt.getlayer(2).type,expect_type)
    res.compare("Code",pkt.getlayer(2).code,expect_code)
    if expect_mtu >= 0:
        res.compare("MTU",pkt.getlayer(2).mtu,expect_mtu)
    if expect_ptr >= 0:
        res.compare("PTR",pkt.getlayer(2).ptr,expect_ptr)
    if expect_id >= 0:
        res.compare("ID",pkt.getlayer(2).id,expect_id)
    if expect_seq >= 0:
        res.compare("SEQ",pkt.getlayer(2).seq,expect_seq)
    return res

####
#  Generic IPv4 Validator
####
expect_ref = None
expect_addr2 = test.public_ipv6_xlate
def ip_val(pkt):
    global expect_code
    global expect_type
    global expect_addr
    global expect_addr2
    global expect_class
    global expect_ptr
    global expect_mtu
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv4",isinstance(pkt.getlayer(1),IP))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Field Comparison
    res.compare("Version",pkt[IP].version,4)
    res.compare("IHL",pkt[IP].ihl,5)
    res.compare("TC",pkt[IP].tos,expect_ref[IPv6].tc)
    #Expected next-header and packet lengths
    expect_len = expect_ref[IPv6].plen+20
    expect_nh = expect_ref[IPv6].nh
    # Validator assumes extension headers are in this order
    # If it has a hop-by-hop header, adjust length / nexthop
    if expect_ref.haslayer(IPv6ExtHdrHopByHop):
        #Length subtracts 8 bytes for extension header
        expect_len -= 8
        #next-hop comes from extension header
        expect_nh = expect_ref[IPv6ExtHdrHopByHop].nh
    # If it has Destination Options, again adjust
    if expect_ref.haslayer(IPv6ExtHdrDestOpt):
        #Length subtracts 8 bytes for extension header
        expect_len -= 8
        #next-hop comes from extension header
        expect_nh = expect_ref[IPv6ExtHdrDestOpt].nh
    # If it has Routing Options, again adjust
    if expect_ref.haslayer(IPv6ExtHdrRouting):
        #Length subtracts 8 bytes for extension header
        expect_len -= 8
        #next-hop comes from extension header
        expect_nh = expect_ref[IPv6ExtHdrRouting].nh
    res.compare("Length",pkt[IP].len,expect_len)
    res.compare("Proto",pkt[IP].proto,expect_nh)
    res.compare("ID",pkt[IP].id,0)
    #Flags are either DF or None depending on packet size
    if expect_len > 1260:
        res.compare("Flags",pkt[IP].flags,"DF")
    else:
        res.compare("Flags",pkt[IP].flags,0)
    res.compare("Frag",pkt[IP].frag,0)
    res.compare("TTL",pkt[IP].ttl,expect_ref[IPv6].hlim-3) #test setup has 3 trips
    res.compare("Src",pkt[IP].src,str(expect_addr))
    res.compare("Dest",pkt[IP].dst,str(expect_addr2))
    res.compare("Payload",pkt[Raw].load,expect_ref[Raw].load)
    return res

#############################################
# IPv4 -> IPv6 (RFC 7915 4.1)
#############################################
def sec_4_1():
    global test
    # Normal Translation Fields
    test.tfail("Normal Translation Fields","Not Implemented")

    # Illegal Source Address
    test.tfail("Illegal Source Address","Not Implemented")

    # IPv4 Source Route Option
    test.tfail("IPv4 Source Route Option","Not Implemented")

    # IPv4 Requires Fragmentation
    test.tfail("IPv4 Requires Fragmentation","Not Implemented")

    test.section("IPv4 -> IPv6 (RFC 7915 4.1)")
#############################################
# ICMPv4 -> ICMPv6 (RFC 7915 4.2)
#############################################
def sec_4_2():
    global test
    global expect_class
    global expect_addr
    global expect_type
    global expect_code
    global expect_id
    global expect_seq
    global expect_mtu
    global expect_ptr
    ####
    #  ICMP PING TYPES (Type 0 / Type 8)
    ####

    # ICMPv4 Echo Request (type 8)
    expect_class = ICMPv6EchoRequest()
    expect_addr = test.public_ipv4_xlate
    expect_type = 128
    expect_code = 0
    expect_id = 22
    expect_seq = 9
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=8,code=0,id=22,seq=9)
    send_and_check(test,send_pkt,icmp6_val, "Echo Request")

    # ICMPv4 Echo Request (type 8)
    expect_class = ICMPv6EchoReply()
    expect_type = 129
    expect_code = 0
    expect_id = 221
    expect_seq = 19
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=0,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Echo Reply")

    #cleanup expects
    expect_id = -1
    expect_seq = -1


    ####
    #  ICMP UNUSUAL TYPES
    ####

    # ICMPv4 Source Quench (Type 4)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=4,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Source Quench")

    # ICMPv4 Redirect (Type 5)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=5,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Redirect")

    # ICMPv4 Alternative Host Address (Type 6)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=6,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Alternative Host Address")

    # ICMPv4 unassigned type 7
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=7,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Unassigned7")

    # ICMPv4 Router Advertisement (Type 9)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=9,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Router Advertisement")

    # ICMPv4 Router Solicitation (Type 10)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=10,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Router Solicitation")

    # ICMPv4 Timestamp (Type 13)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=13,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Timestamp")

    # ICMPv4 Timestamp Reply (Type 14)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=14,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Timestamp Reply")

    # ICMPv4 Information Request (Type 15)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=15,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Information Request")

    # ICMPv4 Information Reply (Type 16)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=16,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Information Reply")

    # ICMPv4 Addr Mask Request (Type 17)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=17,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Addr Mask Request")

    # ICMPv4 Addr Mask Reply (Type 18)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=18,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Addr Mask Reply")

    # ICMPv4 Extended Echo Request (Type 42)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=42,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Extended Echo Request")

    # ICMPv4 Ectended Echo Reply (Type 43)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=43,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Extended Echo Reply")

    ####
    # ICMP Error Messages (Type 3)
    ####

    # ICMPv4 Destination Unreachable - Host Unreachable
    expect_class = ICMPv6DestUnreach()
    expect_addr = test.public_ipv4_xlate
    expect_type = 1
    expect_code = 0
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Destination Unreachable Host Unreachable")

    # ICMPv4 Destination Unreachable - Network Unreachable
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Destination Unreachable Network Unreachable")

    # ICMPv4 Destination Unreachable - Port Unreachable
    expect_code = 4
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=3) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Destination Unreachable Port Unreachable")

    # ICMPv4 Destination Unreachable - Protocol Unreachable
    expect_class = ICMPv6ParamProblem()
    expect_type = 4
    expect_code = 1
    expect_ptr = 6
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=2) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Destination Unreachable Protocol Unreachable")

    # ICMPv4 Fragmentation Needed (and MTU is lower on Tayga)
    expect_class = ICMPv6PacketTooBig()
    expect_type = 2
    expect_code = 0
    expect_mtu = 1460
    expect_ptr = -1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=4,nexthopmtu=1440) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Fragmentation Needed (Normal MTU)")

    # ICMPv4 Fragmentation Needed (and MTU is lower, but would be higher once +20, like PPPoE)
    expect_mtu = 1500
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=4,nexthopmtu=1496) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Fragmentation Needed (Slightly Large MTU)")

    # ICMPv4 Fragmentation Needed (and MTU is less than 1280)
    expect_mtu = 1280
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=4,nexthopmtu=1200) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Fragmentation Needed (Small MTU)")

    # ICMPv4 Fragmentation Needed (and MTU is higher on Tayga)
    expect_mtu = 1500
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=4,nexthopmtu=1600) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Fragmentation Needed (Large MTU)")

    # ICMPv4 Source Route Failed
    expect_class = ICMPv6DestUnreach()
    expect_type = 1
    expect_code = 0
    expect_mtu = -1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=5) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Source Route Failed")

    # ICMPv4 Dest Network Unknown
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Dest Network Unknown")

    # ICMPv4 Dest Host Unknown
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=7) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Dest Host Unknown")

    # ICMPv4 Source Host Isolated
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=8) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Source Host Isolated")

    # ICMPv4 Network Administratively Prohibited
    expect_code = 1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=9) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Newtork Admin Prohibited")

    # ICMPv4 Host Administratively Prohibited
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=10) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Host Admin Prohibited")

    # ICMPv4 Network Unreachable For ToS
    expect_code = 0
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=11) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Network Unreachable for ToS")

    # ICMPv4 Host Unreachable For ToS
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=12) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Host Unreachable for ToS")

    # ICMPv4 Communication Administratively Prohibited
    expect_code = 1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=13) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Communication Administratively Prohibited")

    # ICMPv4 Host Precedence Violation
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=14) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Host Presence Violation")

    # ICMPv4 Precedence Cutoff In Effect
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=15) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Precedence Cutoff In Effect")

    ####
    # ICMP Parameter Problem (Type 12)
    ####

    # ICMPv4 Pointer Indicates Error pointer 0
    expect_class = ICMPv6ParamProblem()
    expect_type = 4
    expect_code = 0
    expect_ptr = 0
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 0 Version/IHL")


    # ICMPv4 Pointer Indicates Error pointer 1
    expect_ptr = 1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 1 Type Of Service")


    # ICMPv4 Pointer Indicates Error pointer 2
    expect_ptr = 4
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=2) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 2 Total Length")


    # ICMPv4 Pointer Indicates Error pointer 3
    expect_ptr = 4
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=3) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 3 Total Length")

    # ICMPv4 Pointer Indicates Error 4, 5, 6,7 all should not be returned
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=4) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 4")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=5) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 5")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 6")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 7")

    # ICMPv4 Pointer Indicates Error pointer 8, 9
    expect_ptr = 7
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=8) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 8 Time To Live")
    expect_ptr = 6
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=9) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error 9 Protocol")

    # ICMPv4 Pointer Indicates Error 10,11 should not be returned
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=10) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 10")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=11) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 11")

    # ICMPv4 Pointer Indicates Error 12-15 are all Source Address
    expect_ptr = 8
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=12) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 12")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=13) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 13")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=14) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 14")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=15) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 15")

    # ICMPv4 Pointer Indicates Error 16-19 are all Dest Address
    expect_ptr = 24
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=16) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 16")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=17) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 17")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=18) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 18")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=19) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Pointer Indicates Error Src Address 19")

    # Pointer Indicates Error 20 (too large)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=0,ptr=20) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Pointer Indicates Error 20")

    # ICMPv4 Missing Required Option
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt, "Missing Required Option")

    # ICMPv4 Bad Length
    expect_ptr = 0
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 0 Version/IHL")


    # ICMPv4 Bad Length pointer 1
    expect_ptr = 1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 1 Type Of Service")


    # ICMPv4 Bad Length pointer 2
    expect_ptr = 4
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=2) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 2 Total Length")


    # ICMPv4 Bad Length pointer 3
    expect_ptr = 4
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=3) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 3 Total Length")

    # ICMPv4 Bad Length 4, 5, 6,7 all should not be returned
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=4) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 4")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=5) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 5")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 6")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 7")

    # ICMPv4 Bad Length pointer 8, 9
    expect_ptr = 7
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=8) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 8 Time To Live")
    expect_ptr = 6
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=9) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length 9 Protocol")

    # ICMPv4 Bad Length 10,11 should not be returned
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=10) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 10")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=11) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 11")

    # ICMPv4 Bad Length 12-15 are all Source Address
    expect_ptr = 8
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=12) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 12")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=13) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 13")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=14) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 14")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=15) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 15")

    # ICMPv4 Bad Length 16-19 are all Dest Address
    expect_ptr = 24
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=16) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 16")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=17) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 17")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=18) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 18")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=19) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Bad Length Src Address 19")

    # Bad Length 20 (invalid)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=2,ptr=20) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Bad Length 20")

    # ICMPv4 Other Param Problem
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=3) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Other Parameter Problem 3")
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=12,code=6) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_none(test,send_pkt,"Other Parameter Problem 4")

    ####
    # ICMPv4 Time Exceeded (Type 11)
    ####

    # ICMPv4 Time Exceeded - Hop Limit
    expect_class = ICMPv6TimeExceeded()
    expect_type = 3
    expect_code = 0
    expect_ptr = -1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=11,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Time Exceeded Hop Limit")

    # ICMPv4 Time Exceeded - Fragment Reassembly
    expect_code = 1
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=11,code=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=8,code=0,id=221,seq=19)
    send_and_check(test,send_pkt,icmp6_val, "Time Exceeded Fragment Reassembly Time")


    test.section("ICMPv4 -> ICMPv6 (RFC 7915 4.2)")

#############################################
# ICMPv4 Packets with Extensions (RFC 7915 4.4 + RFC4884)
#############################################
def sec_4_2_rfc4884():
    global test
    test.tfail("ICMPv4 Packets with Extensions (RFC4884)","Not Implemented")
    test.section("ICMPv4 Packets with Extensions (RFC 7915 4.4 + RFC4884)")

#############################################
# ICMP Inner Translation (RFC 7915 4.3)
#############################################
def sec_4_3():
    # One Nested Header
    test.tfail("One Nested Header","Not Implemented")

    # Two Nested Headers
    test.tfail("Two Nested Headers","Not Implemented")


    test.section("ICMPv4 Inner Translation (RFC 7915 4.3)")

#############################################
# ICMPv4 Generation Cases (RFC 7915 4.4)
#############################################
def sec_4_4():
    global test
    global expect_addr
    global expect_type
    global expect_code
    # Hop Limit Exceeded in Tayga (Data payload)
    expect_addr = test.tayga_ipv4
    expect_type = 11
    expect_code = 0
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_check(test,send_pkt,icmp4_val, "Hop Limit Exceeded in Tayga (UDP)")

    # Hop Limit Exceeded in Tayga (ICMP payload)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / ICMP(type=8,code=0,id=24,seq=71)
    send_and_check(test,send_pkt,icmp4_val, "Hop Limit Exceeded in Tayga (ICMP Echo)")

    # Hop Limit Exceeded in Tayga (ICMP error)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / ICMP(type=3,code=0,id=24,seq=71)
    send_and_none(test,send_pkt, "Hop Limit Exceeded in Tayga (ICMP Error)")

    test.section("ICMPv4 Generation Cases (RFC 7915 4.4)")
#############################################
# Transport-Layer Header (RFC 7915 4.5)
#############################################
def sec_4_5():
    global test
    # TCP Header
    test.tfail("TCP Header","Not Implemented")

    # UDP Header w/ checksum
    test.tfail("UDP Header w/ checksum","Not Implemented")

    # UDP Header w/o checksum
    test.tfail("UDP Header w/o checksum","Not Implemented")

    # ICMP Header
    test.tfail("ICMP Header","Not Implemented")

    # No other protocols are required, but we may want to test them
    test.tfail("Other Protocols","Not Implemented")

    test.section("Transport-Layer Header (RFC 7915 4.5)")
#############################################
# IPv6 to IPv4 Translation (RFC 7915 5.1)
#############################################
def sec_5_1():
    global test
    global expect_ref
    global expect_addr
    global expect_addr2
    expect_addr = test.public_ipv6_xlate
    expect_addr2 = test.public_ipv4

    # Normal Translation
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,plen=64) / Raw(randbytes(64))
    send_and_check(test,expect_ref,ip_val, "Basic Translation Small Packet")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,plen=512) / Raw(randbytes(512))
    send_and_check(test,expect_ref,ip_val, "Basic Translation Medium Packet")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "Basic Translation Larger Packet")

    # TOS value tests
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,tc=24,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "Type Of Service 1")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,tc=48,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "Type Of Service 2")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,tc=96,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "Type Of Service 3")

    # Explicit Congestion Notification
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,tc=1,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "ECN")

    # TOS + ECN
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,tc=25,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "TOS+ECN")

    # TTL Varying
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,hlim=172,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "TTL Big")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16,hlim=5,plen=1420) / Raw(randbytes(1420))
    send_and_check(test,expect_ref,ip_val, "TTL Small")

    # ICMP translation (proto 1 / proto 58) is handled section 5.2 tests

    # IPv6 Hop By Hop Options
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8) / IPv6ExtHdrHopByHop(nh=16) / Raw(randbytes(72))
    send_and_check(test,expect_ref,ip_val, "Hop-By-Hop Option")

    # IPv6 Destination Options
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8) / IPv6ExtHdrDestOpt(nh=16) / Raw(randbytes(72))
    send_and_check(test,expect_ref,ip_val, "Destination Option")

    # IPv6 Route w/ segments left
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8) / IPv6ExtHdrRouting(nh=16,segleft=0,type=253) / Raw(randbytes(72))
    send_and_check(test,expect_ref,ip_val, "Routing w/o segments left")

    # IPv6 Route w/o segments left
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8) / IPv6ExtHdrRouting(nh=16,segleft=4,type=253) / Raw(randbytes(72))
    send_and_none(test,expect_ref, "Routing w/ segments left")

    # Multiple IPv6 Option Headers
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8+8) / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt(nh=16) / Raw(randbytes(72))
    send_and_check(test,expect_ref,ip_val, "Hop-By-Hop + Dest Option")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8+8+8) / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / IPv6ExtHdrRouting(nh=16,segleft=0,type=253) / Raw(randbytes(72))
    send_and_check(test,expect_ref,ip_val, "Hop-By-Hop + Dest + Routing Option")
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=72+8+8) / IPv6ExtHdrHopByHop() / IPv6ExtHdrRouting(nh=16,segleft=4,type=253) / Raw(randbytes(72))
    send_and_none(test,expect_ref, "Hop-By-Hop + Routing Segments Left Option")

    # Fragmentation Needed
    test.tfail("Fragmentation Needed","Not Implemented")

    # IPv6 Fragment Header
    test.tfail("IPv6 Fragment Header","Not Implemented")

    # Illegal Source Address
    test.tfail("Illegal Source Address","Not Implemented")

    # Illegal Dest Address
    test.tfail("Illegal Dest Address","Not Implemented")

    test.section("IPv6 to IPv4 Translation (RFC 7915 5.1)")
#############################################
# ICMPv6 to ICMPv4 Translation (RFC 7915 5.2)
#############################################
def sec_5_2():
    global test
    global expect_addr
    global expect_id
    global expect_type
    global expect_seq
    global expect_code
    global expect_class
    global expect_ptr

    #Expected address is same for all tests
    expect_addr = test.public_ipv6_xlate

    ####
    #  ICMPv6 PING TYPES (Type 128 / Type 129)
    ####

    # ICMPv4 Echo Request
    expect_id = 15
    expect_seq = 21
    expect_type = 8
    expect_code = 0
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6EchoRequest(id=expect_id,seq=expect_seq)
    send_and_check(test,send_pkt,icmp4_val, "Echo Request")

    # ICMPv4 Echo Reply
    expect_id  = 69
    expect_seq = 42
    expect_type = 0
    expect_code = 0
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6EchoReply(id=expect_id,seq=expect_seq)
    send_and_check(test,send_pkt,icmp4_val, "Echo Reply")

    # Clear expected
    expect_id = -1
    expect_seq = -1

    ####
    # MLD (Type 130 / Type 131 / Type 132)
    ####

    # MLD Query
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=130,code=0)
    send_and_none(test,send_pkt,"MLD Query")
    # MLD Report
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=131,code=0)
    send_and_none(test,send_pkt,"MLD Report")
    # MLD Done
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=132,code=0)
    send_and_none(test,send_pkt,"MLD Done")

    ####
    # ND (Type 135 / Type 136 / Type 137))
    ####

    # Neighbor Solicitation
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=135,code=0)
    send_and_none(test,send_pkt,"Neighbor Solicitation")
    # Neighbor Advertisement
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=136,code=0)
    send_and_none(test,send_pkt,"Neighbor Advertisement")
    # Redirect Message
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6Unknown(type=137,code=0)
    send_and_none(test,send_pkt,"Redirect")

    ####
    # Unreachable (Type 1)
    ####


    # No Route to Destination
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "No Route to Destination")

    # Communication Administratively Prohibited
    expect_type = 3
    expect_code = 10
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Administratively Prohibited")

    # Beyond Scope of Source Address
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=2) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Beyond Scope of Source Address")

    # Address Unreachable
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=3) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Address Unreachable")

    # Port Unreachable
    expect_type = 3
    expect_code = 3
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=4) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Port Unreachable")

    # Others should be dropped (TODO?)
    test.tfail("Invalid Error Codes","Not Implemented")

    ####
    # Other Errors (Type 2 / Type 3 / Type 4)
    ####

    # Packet Too Big (w/ MTU in reasonable size)
    expect_type = 3
    expect_code = 4
    expect_mtu = 1340
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6PacketTooBig(mtu=expect_mtu+20) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Packet Too Big")


    # Packet Too Big (w/ MTU above Tayga's MTU)
    expect_type = 3
    expect_code = 4
    expect_mtu = 1480 # clamped from 1500 mtu on Tayga tun adapter
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6PacketTooBig(mtu=1600) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Packet Really Too Big")
    expect_mtu = -1

    # Time Exceeded In Transit
    expect_type = 11
    expect_code = 0
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6TimeExceeded(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Time Exceeded In Transit")

    # Time Exceeded / Fragment Reassembly
    expect_type = 11
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6TimeExceeded(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Time Exceeded Fragment Reassembly")


    # Parameter Problem Erroneous Header
    expect_type = 12
    expect_code = 0
    for i in range(0,41):
        if i > 39: expect_ptr = -1
        elif i > 23: expect_ptr = 16
        elif i > 7: expect_ptr = 12
        elif i > 6: expect_ptr = 8
        elif i > 5 : expect_ptr = 9
        elif i > 3: expect_ptr = 2
        elif i > 1: expect_ptr = -1
        elif i > 0: expect_ptr = 1
        else: expect_ptr = 0
        send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6ParamProblem(code=0,ptr=i) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
        if expect_ptr >= 0: send_and_check(test,send_pkt,icmp4_val, "Parameter Problem Erroneous Header "+str(i))
        else: send_and_none(test,send_pkt, "Parameter Problem Erroneous Header "+str(i))

    # Parameter Proboem Unrecognized Next Header    
    expect_type = 3
    expect_code = 2
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6ParamProblem(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Parameter Problem Unrecognized Header")
    

    # Other Error Types
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6ParamProblem(code=2) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_none(test,send_pkt, "Parameter Problem Other")

    #############################################
    #  ICMPv6 Errors without a mapping address (RFC 7915 5.2)
    #  This scenario happens in 464xlat to the CLAT
    #  if the ICMPv6 error is from an IPv6 router on path
    #############################################

    # Expected source address is Tayga's own address
    expect_addr = test.tayga_ipv4

    # No Route to Destination
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "No Route to Destination")

    # Communication Administratively Prohibited
    expect_type = 3
    expect_code = 10
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Administratively Prohibited")

    # Beyond Scope of Source Address
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=2) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Beyond Scope of Source Address")

    # Address Unreachable
    expect_type = 3
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=3) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Address Unreachable")

    # Port Unreachable
    # Expect nothing, since this particular message can only come
    # from the destination system?
    expect_type = 3
    expect_code = 3
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=4) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Port Unreachable")

    # Packet Too Big (w/ MTU in reasonable size)
    expect_type = 3
    expect_code = 4
    expect_mtu = 1340
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6PacketTooBig(mtu=expect_mtu+20) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Packet Too Big")

    # Packet Too Big (w/ MTU above Tayga's MTU)
    expect_type = 3
    expect_code = 4
    expect_mtu = 1480 # clamped from 1500 mtu on Tayga tun adapter
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6PacketTooBig(mtu=1600) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Packet Really Too Big")
    expect_mtu = -1

    # Time Exceeded In Transit
    expect_type = 11
    expect_code = 0
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6TimeExceeded(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Time Exceeded In Transit")

    # Time Exceeded / Fragment Reassembly
    expect_type = 11
    expect_code = 1
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6TimeExceeded(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
    send_and_check(test,send_pkt,icmp4_val, "Time Exceeded Fragment Reassembly")


    # Parameter Problem Erroneous Header
    test.tfail("Parameter Problem Erroneous Header","Not Implemented")

    # Parameter Proboem Unrecognized Next Header
    test.tfail("Parameter Proboem Unrecognized Next Header","Not Implemented")

    # reset expected
    expect_id = -1
    expect_seq = -1
    expect_mtu = -1

    test.section("ICMPv6 to ICMPv4 Translation (RFC 7915 5.2)")
#############################################
# ICMP Inner Translation (RFC 7915 5.3)
#############################################
def sec_5_3():
    # One Nested Header
    test.tfail("One Nested Header","Not Implemented")

    # Two Nested Headers
    test.tfail("Two Nested Headers","Not Implemented")


    test.section("ICMPv6 Inner Translation (RFC 7915 5.3)")
#############################################
# ICMPv6 Generation (RFC 7915 5.4)
#############################################
def sec_5_4():
    global expect_addr
    global expect_id
    global expect_seq
    global expect_type
    global expect_code
    global expect_class
    expect_addr = test.public_ipv6_xlate

    # Hop Limit Exceeded In Tayga (UDP)
    expect_class = ICMPv6TimeExceeded()
    expect_addr = test.tayga_ipv6
    expect_type = 3
    expect_code = 0
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),hlim=2) / UDP(sport=6969,dport=69,len=72) / Raw(randbytes(64))
    send_and_check(test,send_pkt,icmp6_val, "Hop Limit Exceeded in Tayga (UDP)")
   
    # Hop Limit Exceeded In Tayga (ICMP)
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),hlim=2) / ICMPv6EchoRequest(id=42,seq=89)
    send_and_check(test,send_pkt,icmp6_val, "Hop Limit Exceeded in Tayga (ICMP)")
   
    # Hop Limit Exceeded In Tayga (ICMP Error)
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),hlim=2) / ICMPv6EchoReply(id=43,seq=88)
    send_and_none(test,send_pkt, "Hop Limit Exceeded in Tayga (ICMP Error)")

    # reset expected
    expect_id = -1
    expect_seq = -1

    test.section("ICMPv6 Generation (RFC 7915 5.4)")
#############################################
# Transport-Layer Header (RFC 7915 5.5)
#############################################
def sec_5_5():
    # TCP Header
    test.tfail("TCP Header","Not Implemented")

    # UDP Header w/ checksum
    test.tfail("UDP Header w/ checksum","Not Implemented")

    # UDP Header w/o checksum
    test.tfail("UDP Header w/o checksum","Not Implemented")

    # ICMP Header
    test.tfail("ICMP Header","Not Implemented")

    # No other protocols are required, but we may want to test them   
    test.section("Transport-Layer Header (RFC 7915 5.5)")

    


# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_log_file = "test/translate.log"
test.tayga_bin = "./tayga-cov"
test.pcap_file = "test/translate.pcap"
#test.pcap_test_env = True
test.setup()

# Call all tests
#sec_4_1()
sec_4_2()
#sec_4_2_rfc4884()
#sec_4_3()
#sec_4_4()
#sec_4_5()
#sec_5_1()
sec_5_2()
#sec_5_3()
#sec_5_4()
#sec_5_5()

test.cleanup()
#Print test report
test.report()

