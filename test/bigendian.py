#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/bigendian.py
#   Subset of RFC7915 tests for big-endian hosts
#
# Required packages to install for big-endian support:
# sudo dpkg --add-architecture s390x
# sudo apt update
# sudo apt install gcc-s390x-linux-gnu qemu-user-static libc6:s390x

from test_env import (
    test_env,
    test_result,
    router,
)
from random import randbytes
from scapy.all import IP, ICMP, UDP, IPv6, Raw, TCP
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
)
from scapy.layers.inet import (
    ICMPerror,
    UDPerror
)
import time

## Test Environment global
test = test_env("test/bigendian")

####
#  Generic ICMPv4 Validator
####
expect_type = 0
expect_code = 0
expect_id = -1
expect_seq = -1
expect_mtu = -1
expect_sa = ""
expect_da = ""
expect_csum = -1
def icmp4_val(pkt):
    res = test_result()
    res.check("Contains IP",pkt.haslayer(IP))
    res.check("Contains ICMP",pkt.haslayer(ICMP))
    #Bail early so we don't get derefrence errors
    if (not IP in pkt) or (not ICMP in pkt):
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IP].src,str(expect_sa))
    res.compare("Dst IP",pkt[IP].dst,str(expect_da))
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
    if expect_csum >= 0:
        res.compare("Checksum",pkt[ICMP].chksum,expect_csum)
    return res

####
#  Generic ICMPv6 Validator
####
expect_class = None
expect_ptr = -1
def icmp6_val(pkt):
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv6",isinstance(pkt.getlayer(1),IPv6))
    res.compare("Expected Class",type(pkt.getlayer(2)),type(expect_class))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Validate packet stuff
    res.compare("Src IP",pkt[IPv6].src,str(expect_sa))
    res.compare("Dst IP",pkt[IPv6].dst,str(expect_da))
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
#  Generic IPv6 Validator
####
expect_fl = 0
expect_frag = False
expect_len = -1
def ip6_val(pkt):
    res = test_result()
    # layer 0 is LinuxTunInfo
    res.check("Contains IPv6",isinstance(pkt.getlayer(1),IPv6))
    #Bail early so we don't get derefrence errors
    if res.has_fail:
        return res
    #Field Comparison
    res.compare("Src",pkt[IPv6].src,str(expect_sa))
    res.compare("Dest",pkt[IPv6].dst,str(expect_da))
    res.compare("Version",pkt[IPv6].version,6)
    if expect_data is not None:
        if expect_frag:
            # Only compare first expect_len bytes
            res.compare("Payload",pkt[Raw].load,expect_data[0:expect_len],print=False)
        else:
            res.compare("Payload",pkt[Raw].load,expect_data,print=False)
    if expect_csum < 0:
        pass
    elif pkt.haslayer(TCP):
        res.compare("Checksum TCP",pkt[TCP].chksum,expect_csum)
    elif pkt.haslayer(UDP):
        res.compare("Checksum UDP",pkt[UDP].chksum,expect_csum)
    elif pkt.haslayer(ICMPv6EchoRequest):
        res.compare("Checksum ICMPv6",pkt[ICMPv6EchoRequest].cksum,expect_csum)
    elif pkt.haslayer(ICMPv6EchoReply):
        res.compare("Checksum ICMPv6",pkt[ICMPv6EchoReply].cksum,expect_csum)
    else:
        res.expect("Checksum Non-TCP/UDP/ICMPv6",False,"Cannot check checksum on non-TCP/UDP/ICMPv6 packet")

    if expect_ref is not None:
        res.compare("TC",pkt[IPv6].tc,expect_ref.tos)
        res.compare("FL",pkt[IPv6].fl,expect_fl)
        if expect_frag:
            #Length is total fragment, not including frag hdr
            res.compare("Length",pkt[IPv6].plen,expect_len+8)
        elif expect_len >= 0:
            res.compare("Length",pkt[IPv6].plen,expect_len)
        else:
            res.compare("Length",pkt[IPv6].plen,expect_ref.len - 20)
        if expect_frag:
            res.compare("NH",pkt[IPv6].nh,44)
            res.check("Contains Frag Hdr",isinstance(pkt.getlayer(2),IPv6ExtHdrFragment))
            #Validate frag header
            res.compare("[frag]NH",pkt[IPv6ExtHdrFragment].nh,expect_ref.proto)
            res.compare("[frag]Offset",pkt[IPv6ExtHdrFragment].offset,0)
            res.compare("[frag]M",pkt[IPv6ExtHdrFragment].m,1)
            res.compare("[frag]id",pkt[IPv6ExtHdrFragment].id,expect_id)
        else:
            if expect_ref.proto == 1:
                res.compare("NH",pkt[IPv6].nh,58)
            else:
                res.compare("NH",pkt[IPv6].nh,expect_ref.proto)
        res.compare("HLIM",pkt[IPv6].hlim,expect_ref.ttl-3)
    return res

####
#  Generic IPv4 Validator
####
expect_ref = None
expect_da = test.public_ipv6_xlate
def ip_val(pkt):
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
    res.compare("Length",pkt[IP].len,expect_len)
    res.compare("Proto",pkt[IP].proto,expect_nh)
    #Flags are either DF or None depending on packet size
    if expect_frag:
        pass # Already checked these flags
    elif expect_len > 1260:
        res.compare("Flags",pkt[IP].flags,"DF")
        res.compare("ID",pkt[IP].id,0)
    else:
        res.compare("Flags",pkt[IP].flags,0)
        #ID is psuedo-randomly generated, but must not be zero
        res.check("ID Nonzero",(pkt[IP].id != 0))
    if not expect_frag:
        res.compare("Frag",pkt[IP].frag,0)
    res.compare("TTL",pkt[IP].ttl,expect_ref[IPv6].hlim-3) #test setup has 3 trips
    res.compare("Src",pkt[IP].src,str(expect_sa))
    res.compare("Dest",pkt[IP].dst,str(expect_da))
    res.compare("Payload",pkt[Raw].load,expect_ref[Raw].load)
    # If checksum expected, check it
    if expect_csum < 0:
        pass
    elif pkt.haslayer(TCP):
        res.compare("Checksum TCP",pkt[TCP].chksum,expect_csum)
    elif pkt.haslayer(UDP):
        res.compare("Checksum UDP",pkt[UDP].chksum,expect_csum)
    else:
        res.expect("Checksum Non-TCP/UDP/ICMP",False,"Cannot check checksum on non-TCP/UDP/ICMP packet")
    return res


#############################################
# Transport-Layer Header (RFC 7915 4.5)
#############################################
def sec_4_5():
    global test
    global expect_sa
    global expect_da
    global expect_data
    global expect_ref
    global expect_len
    global expect_frag
    global expect_id
    global expect_csum
    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "drop"
    test.reload()

    # TCP Header
    # Using well-known TCP packet payloads and manually calculated checksums
    expect_data = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_len = 20+16
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) \
        / TCP(sport=666,dport=667,flags="S",seq=420) \
        / Raw(expect_data)
    expect_csum = 48368 #manually calculated
    test.send_and_check(expect_ref,ip6_val, "TCP Header")

    # UDP Header w/ checksum
    expect_len = 8+16
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) \
        / UDP(sport=666,dport=667) \
        / Raw(expect_data)
    expect_csum = 11904 #manually calculated
    test.send_and_check(expect_ref,ip6_val, "UDP Header w/ checksum")
    
    # UDP Header w/o checksum w/ drop behavior
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    test.send_and_none(expect_ref, "UDP Header w/o checksum, drop")

    # UDP Header w/o checksum w/ forward behavior
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "fwd"
    test.reload()
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    expect_csum = 0
    test.send_and_check(expect_ref, ip6_val,"UDP Header w/o checksum, forward")

    # UDP Header w/o checksum w/ calculate behavior
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "calc"
    test.reload()
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    expect_csum = 11904
    test.send_and_check(expect_ref, ip6_val,"UDP Header w/o checksum, calculate")

    # ICMP Headers
    expect_data = None
    expect_len = 8
    expect_proto = 58
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=8,code=0,id=22,seq=9)
    expect_csum = 60372
    test.send_and_check(expect_ref, ip6_val,"ICMP Echo Request")
    expect_ref = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4)) / ICMP(type=0,code=0,id=23,seq=19)
    expect_csum = 60105
    test.send_and_check(expect_ref, ip6_val,"ICMP Echo Reply")

    #Scapy was used with show2() which generates expected checksums, such as this:
    #expect_equiv = IPv6(dst=str(test.public_ipv6),src=str(test.public_ipv4_xlate)) /ICMPv6EchoRequest(id=22,seq=9)
    #expect_equiv.show2()

    #clear expected
    expect_csum = -1
    expect_len = -1

    test.section("Transport-Layer Header (RFC 7915 4.5)")
    
#############################################
# Transport-Layer Header (RFC 7915 5.5)
#############################################
def sec_5_5():
    global test
    global expect_sa
    global expect_da
    global expect_data
    global expect_ref
    global expect_len
    global expect_frag
    global expect_id
    global expect_csum
    global expect_type
    global expect_code

    # Setup config for this section
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "drop"
    test.reload()

    # TCP Header
    # Using well-known TCP packet payloads and manually calculated checksums
    expect_data = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=20+16) \
        / TCP(sport=666,dport=667,flags="S",seq=420) \
        / Raw(expect_data)
    expect_csum = 58108 #manually calculated
    test.send_and_check(expect_ref,ip_val, "TCP Header")

    # UDP Header w/ checksum
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=8+16) \
        / UDP(sport=666,dport=667) \
        / Raw(expect_data)
    expect_csum = 21644 #manually calculated
    test.send_and_check(expect_ref,ip_val, "UDP Header w/ checksum")

    # UDP Header w/o checksum w/ drop behavior
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=8+16) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    expect_csum = 21644 #manually calculated
    test.send_and_none(expect_ref, "UDP Header w/o checksum, drop")
    
    # UDP Header w/o checksum w/ forward behavior
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "fwd"
    test.reload()
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=8+16) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    expect_csum = 0 #manually calculated
    test.send_and_check(expect_ref,ip_val, "UDP Header w/o checksum, forward")
    
    # UDP Header w/o checksum w/ calculate behavior
    test.tayga_conf.default()
    test.tayga_conf.udp_cksum_mode = "calc"
    test.reload()
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),plen=8+16) \
        / UDP(sport=666,dport=667,chksum=0) \
        / Raw(expect_data)
    expect_csum = 21644 #manually calculated
    test.send_and_check(expect_ref,ip_val, "UDP Header w/o checksum, calculate")

    # ICMP Header
    expect_type = 8
    expect_code = 0
    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6EchoRequest(id=15,seq=21)
    expect_csum = 63451 #manually calculated
    test.send_and_check(expect_ref,icmp4_val, "ICMP Header Echo Request")

    expect_ref = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6)) / ICMPv6EchoReply(id=16,seq=22)
    expect_csum = 65497 #manually calculated
    expect_type = 0
    test.send_and_check(expect_ref,icmp4_val, "ICMP Header Echo Reply")

    #equiv packet used to generate checksums
    #expect_equiv = IP(dst=expect_da,src=expect_sa) / ICMP(type=0,id=16,seq=22)
    #expect_equiv.show2()

    #reset expecteds
    expect_type = -1
    expect_code = -1
    expect_csum = -1

    # No other protocols are required, but we may want to test them   
    test.section("Transport-Layer Header (RFC 7915 5.5)")

# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.setup()
test.tayga_bin = "./taygabe"

# Call all tests
sec_4_5()
sec_5_5()

time.sleep(1)

test.cleanup()
#Print test report (expected pass/fail count)
test.report(14,0)

