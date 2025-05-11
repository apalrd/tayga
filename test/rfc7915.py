from test_env import test_env, send_and_check, send_and_none, test_res, test_result
from scapy.all import IPv6
from scapy.all import IP, ICMP, UDP
from scapy.layers.inet6 import (
    ICMPv6DestUnreach,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6Unknown,
    _ICMPv6
)
import time




# Create an instance of TestEnv and call setup()
test = test_env("test/rfc7915")
#test.debug = True
test.timeout = 1
test.tayga_log_file = "test/rfc7915.log"
test.pcap_file = "test/rfc7915.pcap"
test.setup()


# Generic ICMPv4 type/code validator used by tons of tests
expect_type = 0
expect_code = 0
expect_id = 0
expect_seq = 0
expect_mtu = 0
expect_addr = test.public_ipv6_xlate
def icmp4_type_code(pkt):
    global expect_type
    global expect_code
    global expect_id
    global expect_seq
    global expect_mtu
    global expect_addr
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
    if expect_id != 0:
        res.compare("ID",pkt[ICMP].id,expect_id)
    if expect_seq != 0:
        res.compare("Seq",pkt[ICMP].seq,expect_seq)
    if expect_mtu != 0:
        res.compare("MTU",pkt[ICMP].nexthopmtu,expect_mtu)
    return res


#############################################
# IPv4 -> IPv6 (RFC 7915 4.1)
#############################################

# Normal Translation Fields

# Illegal Source Address

# IPv4 Source Route Option

# IPv4 Requires Fragmentation

test.section("IPv4 -> IPv6 (RFC 7915 4.1)")
#############################################
# ICMPv4 -> ICMPv6 (RFC 7915 4.2)
#############################################

####
#  ICMP PING TYPES (Type 0 / Type 8)
####

# icmp echo request validator
def icmp6_val_echo_request(pkt):
    res = test_result()
    res.check("Contains IPv6",pkt.haslayer(IPv6))
    res.check("Contains ICMPv6EchoRequest",pkt.haslayer(ICMPv6EchoRequest))
    #Bail early so we don't get derefrence errors
    if (not IPv6 in pkt) or (not ICMPv6EchoRequest in pkt):
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IPv6].src,str(test.public_ipv4_xlate))
    res.compare("Dst IP",pkt[IPv6].dst,str(test.public_ipv6))
    res.compare("Type",pkt[ICMPv6EchoRequest].type,128)
    res.compare("Code",pkt[ICMPv6EchoRequest].code,0)
    res.compare("ID",pkt[ICMPv6EchoRequest].id,22)
    res.compare("Seq",pkt[ICMPv6EchoRequest].seq,9)
    return res

# ICMPv4 Echo Request (type 8)
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=8,code=0,id=22,seq=9)
send_and_check(test,send_pkt,icmp6_val_echo_request, "Echo Request")

# icmp echo reply validator
def icmp6_val_echo_reply(pkt):
    res = test_result()
    res.check("Contains IPv6",pkt.haslayer(IPv6))
    res.check("Contains ICMPv6EchoReply",pkt.haslayer(ICMPv6EchoReply))
    #Bail early so we don't get derefrence errors
    if (not IPv6 in pkt) or (not ICMPv6EchoReply in pkt):
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IPv6].src,str(test.public_ipv4_xlate))
    res.compare("Dst IP",pkt[IPv6].dst,str(test.public_ipv6))
    res.compare("Type",pkt[ICMPv6EchoReply].type,129)
    res.compare("Code",pkt[ICMPv6EchoReply].code,0)
    res.compare("ID",pkt[ICMPv6EchoReply].id,221)
    res.compare("Seq",pkt[ICMPv6EchoReply].seq,19)
    return res

# ICMPv4 Echo Request (type 8)
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_echo_reply, "Echo Reply")

#stop here
#test.report()
#test.cleanup()
#exit()

####
#  ICMP UNUSUAL TYPES
####

# Validate type() of layers here
expect_type = None
expect_addr = test.public_ipv4_xlate
def icmp6_val_type(pkt):
    global expect_code
    global expect_type
    global expect_addr
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv6",isinstance(pkt.getlayer(1),IPv6))
    res.compare("Expected Type",type(pkt.getlayer(2)),type(expect_type))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Validate packet stuff
    res.check("Force Fail2",False)
    res.compare("Src IP",pkt[IPv6].src,str(expect_addr))
    res.compare("Dst IP",pkt[IPv6].dst,str(test.public_ipv6))
    res.compare("Type",pkt.getlayer(2).type,expect_type)
    res.compare("Code",pkt.getlayer(2).code,expect_code)
    return res

# ICMPv4 Information Request (Type 15)

# ICMPv4 Information Reply (Type 16)

# ICMPv4 Timestamp (Type 13)

# ICMPv4 Timestamp Reply (Type 14)

# ICMPv4 Addr Mask Request (Type 17)

# ICMPv4 Addr Mask Reply (Type 18)

# ICMPv4 Router Advertisement (Type 9)

# ICMPv4 RouterSolicitation (Type 10)

# ICMPv4 Source Quench (Type 4)

# ICMPv4 Redirect (Type 5)

# ICMPv4 Alternative Host Address (Type 6)


####
# ICMP Error Messages (Type 3)
####

# ICMPv4 Destination Unreachable - Host Unreachable
expect_type = ICMPv6DestUnreach()
expect_addr = test.public_ipv6_xlate
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=1) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_type, "Destination Unreachable Host Unreachable")

# ICMPv4 Destination Unreachable - Network Unreachable
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=0) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_type, "Destination Unreachable Network Unreachable")

# ICMPv4 Destination Unreachable - Port Unreachable
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=3) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_type, "Destination Unreachable Port Unreachable")

# ICMPv4 Destination Unreachable - Protocol Unreachable
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=2) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_type, "Destination Unreachable Protocol Unreachable")

# ICMPv4 Fragmentation Needed
expect_type = ICMPv6PacketTooBig()
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=3,code=4,nexthopmtu=1600) / IP(dst=str(test.public_ipv4),src=str(test.public_ipv6_xlate)) / ICMP(type=0,code=0,id=221,seq=19)
send_and_check(test,send_pkt,icmp6_val_type, "Fragmentation Needed")

# ICMPv4 Source Route Failed

# ICMPv4 Dest Network Unknown

# ICMPv4 Dest Host Unknown

# ICMPv4 Source Host Isolated

# ICMPv4 Network Administratively Prohibited

# ICMPv4 Host Administratively Prohibited

# ICMPv4 Network Unreachable For ToS

# ICMPv4 Host Unreachable For ToS

# ICMPv4 Communication Administratively Prohibited

# ICMPv4 Host Precedence Violation

# ICMPv4 Precedence Cutoff In Effect

####
# ICMP Parameter Problem (Type 12)
####

# ICMPv4 Pointer Indicates Error

# ICMPv4 Missing Required Option

# ICMPv4 Bad Length

# ICMPv4 Other Param Problem

####
# ICMPv4 Time Exceeded (Type 11)
####

# ICMPv4 Time Exceeded

####
#  IGMP - todo?
####

####
# ICMPv4 Packets with Extensions (RFC4884)
####

test.section("ICMPv4 -> ICMPv6 (RFC 7915 4.2)")
#############################################
# ICMPv4 Generation Cases (RFC 7915 4.4)
#############################################

# Hop Limit Exceeded in Tayga (Data payload)
expect_addr = test.tayga_ipv4
expect_type = 11
expect_code = 0
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / UDP(sport=6969,dport=69,len=20)
send_and_check(test,send_pkt,icmp4_type_code, "Hop Limit Exceeded in Tayga (UDP)")

# Hop Limit Exceeded in Tayga (ICMP payload)
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / ICMP(type=8,code=0,id=24,seq=71)
send_and_check(test,send_pkt,icmp4_type_code, "Hop Limit Exceeded in Tayga (ICMP Echo)")

# Hop Limit Exceeded in Tayga (ICMP error)
send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),ttl=2) / ICMP(type=3,code=0,id=24,seq=71)
send_and_none(test,send_pkt, "Hop Limit Exceeded in Tayga (ICMP Error)")

test.section("ICMPv4 Generation Cases (RFC 7915 4.4)")
#############################################
# Transport-Layer Header (RFC 7915 4.5)
#############################################

# TCP Header

# UDP Header w/ checksum

# UDP Header w/o checksum

# ICMP Header

# No other protocols are required, but we may want to test them

test.section("Transport-Layer Header (RFC 7915 4.5)")
#############################################
# IPv6 to IPv4 Translation (RFC 7915 5.1)
#############################################

# Normal Translation Fields

# Fragmentation Needed

# Illegal Source Address

# IPv6 Hop By Hop Options Header

# IPv6 Routing Header /w segments left

# IPv6 Fragment Header

test.section("IPv6 to IPv4 Translation (RFC 7915 5.1)")
#############################################
# ICMPv6 to ICMPv4 Translation (RFC 7915 5.2)
#############################################

#In general all tests use this address
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
send_and_check(test,send_pkt,icmp4_type_code, "Echo Request")

# ICMPv4 Echo Reply
expect_id  = 69
expect_seq = 42
expect_type = 0
expect_code = 0
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6EchoReply(id=expect_id,seq=expect_seq)
send_and_check(test,send_pkt,icmp4_type_code, "Echo Reply")

# Zero expected
expect_id = 0
expect_seq = 0

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
send_and_check(test,send_pkt,icmp4_type_code, "No Route to Destination")

# Communication Administratively Prohibited
expect_type = 3
expect_code = 10
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Administratively Prohibited")

# Beyond Scope of Source Address
expect_type = 3
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=2) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Beyond Scope of Source Address")

# Address Unreachable
expect_type = 3
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=3) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Address Unreachable")

# Port Unreachable
expect_type = 3
expect_code = 3
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6DestUnreach(code=4) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Port Unreachable")

# Others should be dropped (TODO?)

####
# Other Errors (Type 2 / Type 3 / Type 4)
####

# Packet Too Big (w/ MTU in reasonable size)
expect_type = 3
expect_code = 4
expect_mtu = 1340
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6PacketTooBig(mtu=expect_mtu+20) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Packet Too Big")


# Packet Too Big (w/ MTU above Tayga's MTU)
expect_type = 3
expect_code = 4
expect_mtu = 1480 # clamped from 1500 mtu on Tayga tun adapter
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6PacketTooBig(mtu=1600) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Packet Really Too Big")
expect_mtu = 0

# Time Exceeded In Transit
expect_type = 11
expect_code = 0
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6TimeExceeded(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Time Exceeded In Transit")

# Time Exceeded / Fragment Reassembly
expect_type = 11
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6TimeExceeded(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Time Exceeded Fragment Reassembly")


# Parameter Problem Erroneous Header

# Parameter Proboem Unrecognized Next Header

# Other Error Types

# todo section 7


test.section("ICMPv6 to ICMPv4 Translation (RFC 7915 5.2)")
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
send_and_check(test,send_pkt,icmp4_type_code, "No Route to Destination")

# Communication Administratively Prohibited
expect_type = 3
expect_code = 10
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Administratively Prohibited")

# Beyond Scope of Source Address
expect_type = 3
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=2) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Beyond Scope of Source Address")

# Address Unreachable
expect_type = 3
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=3) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Address Unreachable")

# Port Unreachable
# Expect nothing, since this particular message can only come
# from the destination system?
expect_type = 3
expect_code = 3
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6DestUnreach(code=4) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Port Unreachable")

# Packet Too Big (w/ MTU in reasonable size)
expect_type = 3
expect_code = 4
expect_mtu = 1340
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6PacketTooBig(mtu=expect_mtu+20) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Packet Too Big")

# Packet Too Big (w/ MTU above Tayga's MTU)
expect_type = 3
expect_code = 4
expect_mtu = 1480 # clamped from 1500 mtu on Tayga tun adapter
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6PacketTooBig(mtu=1600) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Packet Really Too Big")
expect_mtu = 0

# Time Exceeded In Transit
expect_type = 11
expect_code = 0
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6TimeExceeded(code=0) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Time Exceeded In Transit")

# Time Exceeded / Fragment Reassembly
expect_type = 11
expect_code = 1
send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.icmp_router_ipv6)) / ICMPv6TimeExceeded(code=1) / IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) / ICMPv6EchoRequest()
send_and_check(test,send_pkt,icmp4_type_code, "Time Exceeded Fragment Reassembly")


# Parameter Problem Erroneous Header

# Parameter Proboem Unrecognized Next Header

test.section("ICMPv6 Errors without a mapping address (RFC 7915 5.2)")
#############################################
# ICMP Inner Translation (RFC 7915 5.3)
#############################################

# One Nested Header

# Two Nested Headers


test.section("ICMP Inner Translation (RFC 7915 5.3)")
#############################################
# ICMPv6 Generation (RFC 7915 5.4)
#############################################

# Hop Limit Exceeded In Tayga

# Invalid Address?

test.section("ICMPv6 Generation (RFC 7915 5.4)")
#############################################
# Transport-Layer Header (RFC 7915 5.5)
#############################################

# TCP Header

# UDP Header w/ checksum

# UDP Header w/o checksum

# ICMP Header

# No other protocols are required, but we may want to test them   

test.section("Transport-Layer Header (RFC 7915 5.5)")

test.report()
test.cleanup()