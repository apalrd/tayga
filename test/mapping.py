#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/mapping.py - Mapping methods of v4/v6 addresses
#   ref. RFC 6052, 7757
#
from test_env import (
    test_env,
    test_result,
    router
)
from random import randbytes
from scapy.all import IP, UDP, IPv6, Raw
import time
import ipaddress

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
    test.send_and_check(send_pkt,ip_val, "/32 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102::abcd"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/32 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102:ab00::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/32 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:c0a8:102:abcd:ef12:5678:1234"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/32 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:c0a8:102::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/32 v4->v6")


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
    test.send_and_check(send_pkt,ip_val, "/40 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:0002:abcd:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/40 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:fb02::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/40 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:00c0:a801:cd02:1234:5678:1245"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/40 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:c0:a801:2::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/40 v4->v6")


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
    test.send_and_check(send_pkt,ip_val, "/48 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:1:0200:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/48 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:fa01:0200::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/48 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0a8:6901:0200:ef12:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/48 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:0:c0a8:1:200::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/48 v4->v6")

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
    test.send_and_check(send_pkt,ip_val, "/56 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:a8:102:1234:5678"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/56 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:dca8:102::"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/56 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464:0:c0:eda8:102:4567:9817"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/56 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464:0:c0:a8:102::"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/56 v4->v6")

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
    test.send_and_check(send_pkt,ip_val, "/64 v6->v4")
    #v4->v6 with nonzero suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::c0:a801:200:feed"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/64 v6->v4 w/ nonzero suffix")
    #v4->v6 with nonzero u
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::15c0:a801:200:0"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/64 v6->v4 w/ nonzero u")
    #v4->v6 with nonzero u and suffix
    expect_data = randbytes(128)
    send_pkt = IPv6(dst=str("3fff:6464::68c0:a801:200:face"),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/64 v6->v4 w/ nonzero suffix and u")
    #v4 -> v6
    expect_sa = "3fff:6464::c0:a801:200:0"
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/64 v4->v6")

    # /96
    #reconfigure tayga
    test.tayga_conf.default()
    test.reload()
    expect_sa = test.public_ipv6_xlate
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "/96 v6->v4")
    expect_sa = test.public_ipv4_xlate
    expect_da = test.public_ipv6
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "/96 v4->v6")

    # Cleanup
    rt.remove()
    test.section("Variable Prefix Length (RFC 6052 2.2)")

#############################################
# Explicit Address Mapping (RFC 7757 3.2)
# Test cases where suffix lengths are equal
#############################################
def rfc7757_eam():
    global test
    global expect_sa
    global expect_da
    global expect_len
    global expect_proto
    global expect_data

    # EAM mappings w/ addr specified from 0 bit to 24 bits
    # bits of -1 also tests without bits specified
    # For equal and unequal suffix length
    for equal in [True]: #[True,False]
        for bits in [-1,0,1,2,4,8,12,16,20,24]:
            test.flush()

            # Generate test config for this one
            test.tayga_conf.default()
            test.tayga_conf.dynamic_pool = None
            if bits >= 0:
                if equal: test.tayga_conf.map.append(f"10.0.0.0/{32-bits} 2001:db8:beef:0:cafe::/{128-bits}")
                else: test.tayga_conf.map.append(f"10.0.0.0/{32-bits} 2001:db8:beef:0:cafe::/80")
            else:
                #This case doesn't have an unequal so it runs twice
                test.tayga_conf.map.append("10.0.0.0 2001:db8:beef:0:cafe::0")
            if not equal:
                print(test.tayga_conf.map)
            test.reload()
            if equal: test_nm = f"{bits} bits equal"
            else: test_nm = f"{bits} bits unequal"


            # Routers for this test
            rt_v4 = router(f"8.0.0.0/6")
            rt_v6 = router(f"2001:db8:beef::/64")

            # Addressing
            if bits > 0:
                this_net4 = ipaddress.ip_network(f"10.0.0.0/{32-bits}")
                this_net6 = ipaddress.ip_network(f"2001:db8:beef:0:cafe::/{128-bits}")
            else:
                this_net4 = ipaddress.ip_network("10.0.0.0/32")
                this_net6 = ipaddress.ip_network("2001:db8:beef:0:cafe::/128")


            # Send valid packets (min and max within range)
            # Then invalid packets (just out of range)
            # Do this for v4->v6 and v6->v4
            # Also do this where our addr is in src and in dest

            #v4 -> v6 dest
            expect_sa = test.public_ipv4_xlate
            expect_da = this_net6.network_address
            expect_data = randbytes(128)
            expect_len = 128
            rt_v4.apply()
            send_pkt = IP(dst=str(this_net4.network_address),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" dest min v4->v6")
            expect_da = this_net6.broadcast_address
            expect_data = randbytes(128)
            send_pkt = IP(dst=str(this_net4.broadcast_address),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" dest max v4->v6")

        
            # Send Invalid packets (just out of range
            #v4 -> v6
            expect_data = randbytes(128)
            expect_len = 128
            send_pkt = IP(dst=str(this_net4.network_address-1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
            test.send_and_none(send_pkt, test_nm+" dest under v4->v6")
            expect_data = randbytes(128)
            send_pkt = IP(dst=str(this_net4.broadcast_address+1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
            test.send_and_none(send_pkt, test_nm+" dest over v4->v6")
            rt_v4.remove()

            #v4 -> v6 src
            expect_da = test.public_ipv6
            expect_sa = this_net6.network_address
            expect_data = randbytes(128)
            expect_len = 128
            send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(this_net4.network_address),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" src min v4->v6")
            expect_sa = this_net6.broadcast_address
            expect_data = randbytes(128)
            send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(this_net4.broadcast_address),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" src max v4->v6")

        
            # Send Invalid packets (just out of range)
            # In this case, they come back from the rfc6052 mapping
            #v4 -> v6
            expect_data = randbytes(128)
            expect_da = test.public_ipv6
            expect_sa = test.xlate(str(this_net4.network_address-1))
            expect_len = 128
            send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(this_net4.network_address-1),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" src under v4->v6")
            expect_sa = test.xlate(str(this_net4.broadcast_address+1))
            expect_data = randbytes(128)
            send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(this_net4.broadcast_address+1),proto=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip6_val, test_nm+" src over v4->v6")

            # Restart Tayga to catch any caching issues here
            test.reload()
            rt_v6.apply()
            #v6 -> v4
            expect_sa = test.public_ipv6_xlate
            expect_da = this_net4.network_address
            expect_data = randbytes(128)
            expect_len = 128+20
            send_pkt = IPv6(dst=str(this_net6.network_address),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip_val, test_nm+" dest min v6->v4")
            expect_sa = test.public_ipv6_xlate
            expect_da = this_net4.broadcast_address
            expect_data = randbytes(128)
            expect_len = 128+20
            send_pkt = IPv6(dst=str(this_net6.broadcast_address),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip_val, test_nm+" dest max v6->v4")

            # For invalid, we expect an ICMPv6 back
            expect_sa = test.tayga_ipv6
            expect_da = test.public_ipv6
            expect_data = None
            expect_len = -1
            expect_proto = 58
            send_pkt = IPv6(dst=str(this_net6.network_address-1),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
            test.send_and_check(send_pkt,ip6_val, test_nm+" dest under v6->v4")
            send_pkt = IPv6(dst=str(this_net6.broadcast_address+1),src=str(test.public_ipv6),nh=16) / Raw(randbytes(128))
            test.send_and_check(send_pkt,ip6_val, test_nm+" dest over v6->v4")

            
            # Clear some expecteds
            expect_proto = 16
            rt_v6.remove()

            #v6 -> v4 SA
            expect_sa = this_net4.network_address
            expect_da = test.public_ipv4
            expect_data = randbytes(128)
            expect_len = 128+20
            send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(this_net6.network_address),nh=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip_val, test_nm+" src min v6->v4")
            expect_sa = this_net4.broadcast_address
            expect_da = test.public_ipv4
            expect_data = randbytes(128)
            expect_len = 128+20
            send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(this_net6.broadcast_address),nh=16) / Raw(expect_data)
            test.send_and_check(send_pkt,ip_val, test_nm+" src max v6->v4")

            # For invalid, we expect it to pull from dynamic pool
            expect_sa = test.tayga_ipv6
            expect_da = this_net6.network_address-1
            expect_data = None
            expect_len = -1
            expect_proto = 58
            send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(this_net6.network_address-1),nh=16) / Raw(randbytes(128))
            test.send_and_check(send_pkt,ip6_val, test_nm+" src under v6->v4")
            expect_da = this_net6.broadcast_address+1
            send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str(this_net6.broadcast_address+1),nh=16) / Raw(randbytes(128))
            test.send_and_check(send_pkt,ip6_val, test_nm+" src over v6->v4")

            
            # Clear some expecteds
            expect_proto = 16

    # Fail unequal lengths until #37 is resolved
    # That is commented out as it Tayga will exit with error
    test.tfail("Unequal Suffix Legnths","See Issue #37")

    ####
    #  Overlapping EAM Regions
    #  Should use longest-prefix-match
    ####
    
    # Generate test config for this one
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None
    # Explicitly define /16 mapping
    # Then /24 mapping
    # Then /32 mapping
    # in reverse order
    test.tayga_conf.map.append("10.0.0.0/16 2001:db8:beef:0:cafe::/112")
    test.tayga_conf.map.append("10.0.1.0/24 2001:db8:beef:0:1234::100/120")
    test.tayga_conf.map.append("10.0.1.6 2001:db8:beef:0:5678::106")
    test.reload()

    # Routers for this test
    rt_v4 = router(f"8.0.0.0/6")
    rt_v6 = router(f"2001:db8:beef::/64")

    net1_v4 = ipaddress.ip_network("10.0.0.0/16")
    net1_v6 = ipaddress.ip_network("2001:db8:beef:0:cafe::/112")
    net2_v4 = ipaddress.ip_network("10.0.1.0/24")
    net2_v6 = ipaddress.ip_network("2001:db8:beef:0:1234::100/120")
    net3_v4 = ipaddress.ip_network("10.0.1.6/32")
    net3_v6 = ipaddress.ip_network("2001:db8:beef:0:5678::106/128")

    # Overall, we test:
    # Under net2 (within net1)
    # Min of net2
    # Under net3 (within net2)
    # Explit address (net3)
    # Over net3 (within net2)
    # Max of net2
    # Over net2 (within net1)

    #v4 -> v6 dest
    expect_sa = test.public_ipv4_xlate
    expect_da = net1_v6.network_address + 255
    expect_data = randbytes(128)
    expect_len = 128
    rt_v4.apply()
    send_pkt = IP(dst=str(net2_v4.network_address-1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest under net2 v4->v6")
    expect_da = net2_v6.network_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net2_v4.network_address),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest min net2 v4->v6")
    expect_da = net2_v6.network_address+5
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net3_v4.network_address-1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest under net3 v4->v6")
    expect_da = net3_v6.network_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net3_v4.network_address),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest equal net3 v4->v6")
    expect_da = net2_v6.network_address+7
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net3_v4.network_address+1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest over net3 v4->v6")
    expect_da = net2_v6.broadcast_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net2_v4.broadcast_address),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest max net2 v4->v6")
    expect_da = net1_v6.network_address+512
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(net2_v4.broadcast_address+1),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap dest over net2 v4->v6")
    rt_v4.remove()

    # v4->v6 src    
    expect_da = test.public_ipv6
    expect_sa = net1_v6.network_address + 255
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net2_v4.network_address-1),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src under net2 v4->v6")
    expect_sa = net2_v6.network_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net2_v4.network_address),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src min net2 v4->v6")
    expect_sa = net2_v6.network_address+5
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net3_v4.network_address-1),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src under net3 v4->v6")
    expect_sa = net3_v6.network_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net3_v4.network_address),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src equal net3 v4->v6")
    expect_sa = net2_v6.network_address+7
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net3_v4.network_address+1),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src over net3 v4->v6")
    expect_sa = net2_v6.broadcast_address
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net2_v4.broadcast_address),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src max net2 v4->v6")
    expect_sa = net1_v6.network_address+512
    expect_data = randbytes(128)
    send_pkt = IP(dst=str(test.public_ipv6_xlate),src=str(net2_v4.broadcast_address+1),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "overlap src over net2 v4->v6")


    ## This section will crash Tayga
    ## So it has been commented out
    test.tfail("IPv6 Overlapping Ranges","See Issue #10")
    test.section("Explicit Address Mapping (RFC 7757 3.2)")
    return


    # Generate test config for this one
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None
    # Regions which overlap in IPv6 this time
    test.tayga_conf.map.append("10.0.0.0/16 2001:db8:beef:0:cafe::/112")
    test.tayga_conf.map.append("11.0.0.0/24 2001:db8:beef:0:cafe::100/120")
    test.tayga_conf.map.append("9.1.2.3/32  2001:db8:beef:0:cafe::106/128")
    test.reload()

    
    net1_v4 = ipaddress.ip_network("10.0.0.0/16")
    net1_v6 = ipaddress.ip_network("2001:db8:beef:0:cafe::/112")
    net2_v4 = ipaddress.ip_network("10.0.0.0/24")
    net2_v6 = ipaddress.ip_network("2001:db8:beef:0:cafe::100/120")
    net3_v4 = ipaddress.ip_network("9.1.2.3/32")
    net3_v6 = ipaddress.ip_network("2001:db8:beef:0:cafe::106/128")

    # v6->v4 dest
    test.reload()
    rt_v6.apply()
    expect_sa = test.public_ipv6_xlate
    expect_da = net1_v4.network_address+255
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(net2_v6.network_address-1),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, test_nm+" dest min v6->v4")
    expect_sa = test.public_ipv6_xlate
    expect_da = this_net4.broadcast_address
    expect_data = randbytes(128)
    expect_len = 128+20
    send_pkt = IPv6(dst=str(this_net6.broadcast_address),src=str(test.public_ipv6),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, test_nm+" dest max v6->v4")

    # v6->v4 src






#############################################
# Dynamic Pool Mapping (not specified by RFCs)
#############################################
def dynamic_pool():
    global expect_sa
    global expect_da
    global expect_data
    global expect_len
    global expect_proto
    global test

    # Default configuration for this test
    test.tayga_conf.default()
    test.reload()

    # Send a v4->v6 without the mapping established (should kick back ICMP)
    expect_da = test.public_ipv4
    expect_sa = test.tayga_ipv4
    expect_data = None
    expect_len = -1
    expect_proto = 1
    send_pkt = IP(dst=str("172.16.0.80"),src=str(test.public_ipv4),proto=16) / Raw(randbytes(128))
    test.send_and_check(send_pkt,ip_val, "send packet to map range without mapping")

    # Send a packet to establish the mapping
    expect_sa = "172.16.0.80" #This depends on Tayga's hashing algorithm
    expect_da = test.public_ipv4
    expect_data = randbytes(128)
    expect_len = 128+20
    expect_proto = 16
    send_pkt = IPv6(dst=str(test.public_ipv4_xlate),src=str("2001:db8::69"),nh=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip_val, "send packet to establish mapping")

    # Send a v4->v6 with the mapping established
    expect_da = "2001:db8::69"
    expect_sa = test.public_ipv4_xlate
    expect_data = randbytes(128)
    expect_len = 128
    send_pkt = IP(dst=str("172.16.0.80"),src=str(test.public_ipv4),proto=16) / Raw(expect_data)
    test.send_and_check(send_pkt,ip6_val, "send packet to map range with mapping")

    
    test.section("Dynamic Pool Mapping (not specified by RFCs)")




# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_bin = "./tayga-cov"
test.setup()

# Call all tests
#rfc6052_mapping()
#rfc7757_eam()
dynamic_pool()

time.sleep(1)
test.cleanup()
#Print test report
test.report()
