#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/mapfile.py
#   Test dynamic reloading of mapping entries
#
import time
import ipaddress
from random import randbytes
from scapy.all import IP, IPv6, Raw
from test_env import (
    test_env,
    test_result,
    route_dest,
    router,
)

## Test Environment global
test = test_env("test/mapfile")

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


####
#  Helpers for common operations
####
def send_v4_mapped(v4_dst, v6_expected_dst, label):
    global expect_sa, expect_da, expect_len, expect_proto, expect_data
    rt = router(v4_dst)
    rt.apply()
    expect_proto = 16
    expect_len   = 128
    expect_data  = randbytes(128)
    expect_sa    = test.public_ipv4_xlate
    expect_da    = v6_expected_dst
    pkt = IP(dst=str(v4_dst), src=str(test.public_ipv4), proto=16) / Raw(expect_data)
    test.send_and_check(pkt, ip6_val, label)


def send_v6_mapped(v6_dst, v4_expected_dst, label):
    global expect_sa, expect_da, expect_len, expect_proto, expect_data    
    rt = router(v6_dst)
    rt.apply()
    expect_proto = 16
    expect_len   = 128 + 20
    expect_data  = randbytes(128)
    expect_sa    = test.public_ipv6_xlate
    expect_da    = v4_expected_dst
    pkt = IPv6(dst=str(v6_dst), src=str(test.public_ipv6), nh=16) / Raw(expect_data)
    test.send_and_check(pkt, ip_val, label)


#If a v4 packet is 'rejected', it is translated per rfc6052 instead of a static map entry
def send_v4_rejected(v4_dst, label):
    global expect_sa, expect_da, expect_len, expect_proto, expect_data
    rt = router(v4_dst)
    rt.apply()
    expect_proto = 16
    expect_len   = 128
    expect_data  = randbytes(128)
    expect_sa    = test.public_ipv4_xlate
    expect_da    = test.xlate(v4_dst)
    pkt = IP(dst=str(v4_dst), src=str(test.public_ipv4), proto=16) / Raw(expect_data)
    test.send_and_check(pkt, ip6_val, label)

#No such luck with v6, it truly will reject with ICMP
def send_v6_rejected(v6_dst, label):
    global expect_sa, expect_da, expect_len, expect_proto, expect_data
    rt = router(v6_dst)
    rt.apply()
    expect_proto = 58
    expect_len   = -1
    expect_data  = None
    expect_sa    = test.tayga_ipv6
    expect_da    = test.public_ipv6
    pkt = IPv6(dst=str(v6_dst), src=str(test.public_ipv6), nh=16) / Raw(randbytes(128))
    test.send_and_check(pkt, ip6_val, label)




# ---------------------------------------------------------------------------
# Reloading test cases
#
# Each iteration writes a new map file, reloads, then probes all three
# address pairs (+1, +2, +3) to verify what is and isn't mapped.
# The sequence exercises every branch in addrmap_entry/addrmap_reload
# where both mapping types are static maps
# ---------------------------------------------------------------------------
def test_reloading():
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    map_v4 = ipaddress.ip_address("192.168.2.0")
    map_v6 = ipaddress.ip_address("2001:db8:1::0")

    # startup: [1->1, 2->2]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
    ]
    test.reload()

    #Route pref64 to test system to avoid packet loops
    #Must be more specific than /96 to take precedence
    rt_pref = router("3fff:6464::c000:0000/100",route_dest.ROUTE_TEST)
    rt_pref.apply()

    # Startup test
    send_v4_mapped(map_v4+1, map_v6+1, "startup: v4 1->1 present")
    send_v4_mapped(map_v4+2, map_v6+2, "startup: v4 2->2 present")
    send_v6_mapped(map_v6+1, map_v4+1, "startup: v6 1->1 present")
    send_v6_mapped(map_v6+2, map_v4+2, "startup: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "startup: v4 3 absent")
    send_v6_rejected(map_v6+3,         "startup: v6 3 absent")

    # iter 1: [1->1, 2->2] — no-op, file unchanged (n1==n2, line_no refresh only)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+1, map_v6+1, "iter 1: v4 2->2 present")
    send_v4_mapped(map_v4+2, map_v6+2, "iter 1: v4 2->2 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 1: v6 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 1: v6 2->2  present")
    send_v4_rejected(map_v4+3,         "iter 1: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 1: v6 3 absent")

    # iter 2: [1->1, 2->2, 3->3] — add entry 3 (!m4 && !m6)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
        f"{map_v4+3} {map_v6+3}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+1, map_v6+1, "iter 2: v4 1->1 present")
    send_v4_mapped(map_v4+2, map_v6+2, "iter 2: v4 2->2 present")
    send_v4_mapped(map_v4+3, map_v6+3, "iter 2: v4 3->3 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 2: v6 1->1 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 2: v6 2->2 present")
    send_v6_mapped(map_v6+3, map_v4+3, "iter 2: v6 3->3 present")

    # iter 3: [1->1, 3->3] — delete entry 2
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+3} {map_v6+3}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+1, map_v6+1, "iter 3: v4 1->1 present")
    send_v4_rejected(map_v4+2,         "iter 3: v4 2 absent")
    send_v4_mapped(map_v4+3, map_v6+3, "iter 3: v4 3->3 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 3: v6 1->1 present")
    send_v6_rejected(map_v6+2,         "iter 3: v6 2 absent")
    send_v6_mapped(map_v6+3, map_v4+3, "iter 3: v6 3->3 present")

    # iter 4: [1->1, 3->1] — update IPv6 side of entry 2 (both-sides-conflict)
    # This will conflict with previous version of 3->3, and new 1->1
    # This will evict the 1->1 mapping with the later 3->1 mapping
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+3} {map_v6+1}",
    ]
    test.reconf()
    send_v4_rejected(map_v4+1,         "iter 4: v4 1 absent")
    send_v4_rejected(map_v4+2,         "iter 4: v4 2 absent")
    send_v4_mapped(map_v4+3, map_v6+1, "iter 4: v4 3->1 present")
    send_v6_mapped(map_v6+1, map_v4+3, "iter 4: v6 1->3 present")
    send_v6_rejected(map_v6+2,         "iter 4: v6 2 absent")
    send_v6_rejected(map_v6+3,         "iter 4: v6 3 absent")

    # iter 5: [2->2, 1->2] — update IPv4 side of entry 1 (both-sides-conflict)
    # This will conflict with the new 2->2, and the old 3->1
    # This will evict the 2->2 mapping with the later 2->1 mapping
    test.tayga_conf.map_file_entries = [
        f"{map_v4+2} {map_v6+2}",
        f"{map_v4+2} {map_v6+1}",
    ]
    test.reconf()
    send_v4_rejected(map_v4+1,         "iter 5: v4 1 absent")
    send_v4_mapped(map_v4+2, map_v6+1, "iter 5: v4 2->1 present")
    send_v4_rejected(map_v4+3,         "iter 5: v4 3 absent")
    send_v6_mapped(map_v6+1, map_v4+2, "iter 5: v6 1->2 present")
    send_v6_rejected(map_v6+2,         "iter 5: v6 2 absent")
    send_v6_rejected(map_v6+3,         "iter 5: v6 3 absent")

    # iter 6: [2->3] — update IPv6 side (m4-only conflict)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+2} {map_v6+1}",
        f"{map_v4+2} {map_v6+3}",
    ]
    test.reconf()
    send_v4_rejected(map_v4+1,         "iter 6: v4 1 absent")
    send_v4_mapped(map_v4+2, map_v6+3, "iter 6: v4 2->3 present")
    send_v4_rejected(map_v4+3,         "iter 6: v4 3 absent")
    send_v6_rejected(map_v6+1,         "iter 6: v6 1 absent")
    send_v6_rejected(map_v6+2,         "iter 6: v6 2 absent")
    send_v6_mapped(map_v6+3, map_v4+2, "iter 6: v6 3->2 present")

    # iter 7: [2->1] — update IPv4 side (m6-only conflict)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+2} {map_v6+3}",
        f"{map_v4+1} {map_v6+3}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+1, map_v6+3, "iter 7: v4 1->3 present")
    send_v4_rejected(map_v4+2,         "iter 7: v4 2 absent")
    send_v4_rejected(map_v4+3,         "iter 7: v4 3 absent")
    send_v6_rejected(map_v6+1,         "iter 7: v6 1 absent")
    send_v6_rejected(map_v6+2,         "iter 7: v6 2 absent")
    send_v6_mapped(map_v6+3, map_v4+1, "iter 7: v6 3->1 present")

    # iter 8: replace host entry with shorter-prefix (wider net) covering it
    # 1->3 mapping entry should be replaced since it overlaps with a later map
    # Note that overlapping entries is still considered a configuration error
    map_v4_net = ipaddress.ip_network(f"{map_v4}/30", strict=True)
    map_v6_net = ipaddress.ip_network(f"{map_v6}/126", strict=True)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+3}",
        f"{map_v4_net} {map_v6_net}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+0, map_v6+0, "iter 8: v4 0->0 present via net")
    send_v4_mapped(map_v4+1, map_v6+1, "iter 8: v4 1->1 present via net")
    send_v4_mapped(map_v4+2, map_v6+2, "iter 8: v4 2->2 present via net")
    send_v4_mapped(map_v4+3, map_v6+3, "iter 8: v4 3->3 present via net")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 8: v6 0->0 present via net")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 8: v6 1->1 present via net")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 8: v6 2->2 present via net")
    send_v6_mapped(map_v6+3, map_v4+3, "iter 8: v6 3->3 present via net")

    # iter 9: replace net with longer-prefix (narrower) host entry overlapping it
    test.tayga_conf.map_file_entries = [
        f"{map_v4_net} {map_v6_net}",
        f"{map_v4+3} {map_v6+3}",
    ]
    test.reconf()
    send_v4_rejected(map_v4+0,         "iter 9: v4 0 absent (net gone)")
    send_v4_rejected(map_v4+1,         "iter 9: v4 1 absent (net gone)")
    send_v4_rejected(map_v4+2,         "iter 9: v4 2 absent (net gone)")
    send_v4_mapped(map_v4+3, map_v6+3, "iter 9: v4 3->3 present via host")
    send_v6_rejected(map_v6+0,         "iter 9: v6 0 absent (net gone)")
    send_v6_rejected(map_v6+1,         "iter 9: v6 1 absent (net gone)")
    send_v6_rejected(map_v6+2,         "iter 9: v6 2 absent (net gone)")
    send_v6_mapped(map_v6+3, map_v4+3, "iter 9: v6 3->3 present via host")

    # iter 10: empty file removes all map-file entries
    test.tayga_conf.map_file_entries = []
    test.reconf()
    send_v4_rejected(map_v4+1, "iter 10: v4 1 absent")
    send_v4_rejected(map_v4+2, "iter 10: v4 2 absent")
    send_v4_rejected(map_v4+3, "iter 10: v4 3 absent")
    send_v6_rejected(map_v6+1, "iter 10: v6 1 absent")
    send_v6_rejected(map_v6+2, "iter 10: v6 2 absent")
    send_v6_rejected(map_v6+3, "iter 10: v6 3 absent")

    test.section("Map-File: Reloading")


# ---------------------------------------------------------------------------
# Conflict test cases
#
# These test cases where the map-file entries conflict with other entries
# which cannot be dynamically modified. 
# ---------------------------------------------------------------------------
def test_conflicts():
    global expect_sa, expect_da, expect_len, expect_proto, expect_data
    #Route pref64 to test system to avoid packet loops
    #Must be more specific than /96 to take precedence
    rt_pref = router("3fff:6464::c000:0000/100",route_dest.ROUTE_TEST)
    rt_pref.apply()

    # iter 1a/b: map file conflicts with conf file (v4 conflict case)
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    map_v4 = ipaddress.ip_address("192.168.2.0")
    map_v6 = ipaddress.ip_address("2001:db8:1::0")

    # map file: [1->1, 2->2]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
    ]
    # conf fle: [2->3]
    test.tayga_conf.map.append(f"{map_v4+2} {map_v6+3}")
    test.reload()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 1a: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 1a: v6 1->1 present")
    #[2->3] should take precedence
    send_v4_mapped(map_v4+2, map_v6+3, "iter 1a: v4 2->3 present")
    send_v6_mapped(map_v6+3, map_v4+2, "iter 1a: v6 3->2 present")
    send_v4_rejected(map_v4+3,         "iter 1a: v4 3 absent")
    send_v6_rejected(map_v6+2,         "iter 1a: v6 2 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 1b: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 1b: v6 1->1 present")
    #[2->3] should take precedence
    send_v4_mapped(map_v4+2, map_v6+3, "iter 1b: v4 2->3 present")
    send_v6_mapped(map_v6+3, map_v4+2, "iter 1b: v6 3->2 present")
    send_v4_rejected(map_v4+3,         "iter 1b: v4 3 absent")
    send_v6_rejected(map_v6+2,         "iter 1b: v6 2 absent")


    # iter 2a/b: map file conflicts with conf file (v6 conflict case)
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    # map file: [1->1, 2->2]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
    ]
    # conf fle: [2->3]
    test.tayga_conf.map.append(f"{map_v4+3} {map_v6+2}")
    test.reload()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 2a: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 2a: v6 1->1 present")
    #[3->2] should take precedence
    send_v4_mapped(map_v4+3, map_v6+2, "iter 2a: v4 3->2 present")
    send_v6_mapped(map_v6+2, map_v4+3, "iter 2a: v6 2->3 present")
    send_v4_rejected(map_v4+2,         "iter 2a: v4 2 absent")
    send_v6_rejected(map_v6+3,         "iter 2a: v6 3 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 2b: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 2b: v6 1->1 present")
    #[3->2] should take precedence
    send_v4_mapped(map_v4+3, map_v6+2, "iter 2b: v4 3->2 present")
    send_v6_mapped(map_v6+2, map_v4+3, "iter 2b: v6 2->3 present")
    send_v4_rejected(map_v4+2,         "iter 2b: v4 2 absent")
    send_v6_rejected(map_v6+3,         "iter 2b: v6 3 absent")


    # iter 3a/b/c: map file conflicts with conf file (both same)
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    # map file: [1->1, 2->2]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} {map_v6+2}",
    ]
    # conf fle: [2->3]
    test.tayga_conf.map.append(f"{map_v4+2} {map_v6+2}")
    test.reload()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 3a: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 3a: v6 1->1 present")
    #[2->2] should load either way
    send_v4_mapped(map_v4+2, map_v6+2, "iter 3a: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 3a: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 3a: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 3a: v6 3 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 3b: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 3b: v6 1->1 present")
    #[2->2] should load either way
    send_v4_mapped(map_v4+2, map_v6+2, "iter 3b: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 3b: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 3b: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 3b: v6 3 absent")

    #Now, remove map-file entry and ensure that conf file entry not deleted
    # map file: [1->1]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
    ]
    test.reconf()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 3c: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 3c: v6 1->1 present")
    #[2->2] should remain since it is from the conf file
    send_v4_mapped(map_v4+2, map_v6+2, "iter 3c: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 3c: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 3c: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 3c: v6 3 absent")


    # iter 4a/b/c: map file conflicts with conf file (both different)
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    # map file: [1->1, 2->2]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+2}",
        f"{map_v4+2} {map_v6+1}",
    ]
    # conf fle: [2->3]
    test.tayga_conf.map.append(f"{map_v4+2} {map_v6+2}")
    test.reload()

    # addresses 1 should be overwritten since they overlap with conf file
    send_v4_rejected(map_v4+1,         "iter 4a: v4 1 absent")
    send_v6_rejected(map_v6+1,         "iter 4a: v6 1 absent")
    #[2->2] should load from conf file
    send_v4_mapped(map_v4+2, map_v6+2, "iter 4a: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 4a: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 4a: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 4a: v6 3 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()

    # addresses 1 should be overwritten since they overlap with conf file
    send_v4_rejected(map_v4+1,         "iter 4b: v4 1 absent")
    send_v6_rejected(map_v6+1,         "iter 4b: v6 1 absent")
    #[2->2] should load from conf file
    send_v4_mapped(map_v4+2, map_v6+2, "iter 4b: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 4b: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 4b: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 4b: v6 3 absent")

    #Now, remove map-file entries and ensure that conf file entry not deleted
    # map file: [1->1]
    test.tayga_conf.map_file_entries = []
    test.reconf()
    # addresses 1 should be overwritten since they overlap with conf file
    send_v4_rejected(map_v4+1,         "iter 4c: v4 1 absent")
    send_v6_rejected(map_v6+1,         "iter 4c: v6 1 absent")
    #[2->2] should load from conf file
    send_v4_mapped(map_v4+2, map_v6+2, "iter 4c: v4 2->2 present")
    send_v6_mapped(map_v6+2, map_v4+2, "iter 4c: v6 2->2 present")
    send_v4_rejected(map_v4+3,         "iter 4c: v4 3 absent")
    send_v6_rejected(map_v6+3,         "iter 4c: v6 3 absent")


    # iter 5a/b/c: map file conflicts with tayga's own ipv4 address
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    # map file
    test.tayga_conf.map_file_entries = [
        f"{test.tayga_ipv4} {map_v6+2}"
    ]
    test.reload()

    # Tayga will kick back 'ICMP Protocol Unreachable' in this case
    # and not allow the mapping to be created (no v6->v4 path)
    expect_proto = 1
    expect_data  = None
    expect_sa = test.tayga_ipv4
    expect_da = test.public_ipv4
    expect_len = -1
    pkt = IP(dst=str(test.tayga_ipv4), src=str(test.public_ipv4), proto=16) / Raw(randbytes(128))
    test.send_and_check(pkt, ip_val, "iter 5a: v4 icmp proto unreach")
    send_v6_rejected(map_v6+2,       "iter 5a: v6 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()
    expect_proto = 1
    expect_data  = None
    expect_sa = test.tayga_ipv4
    expect_da = test.public_ipv4
    expect_len = -1
    pkt = IP(dst=str(test.tayga_ipv4), src=str(test.public_ipv4), proto=16) / Raw(randbytes(128))
    test.send_and_check(pkt, ip_val, "iter 5b: v4 icmp proto unreach")
    send_v6_rejected(map_v6+2,       "iter 5b: v6 absent")

    #Now, remove map-file entries and ensure that the mapping is not deleted still
    # map file: [1->1]
    test.tayga_conf.map_file_entries = []
    test.reconf()
    expect_proto = 1
    expect_data  = None
    expect_sa = test.tayga_ipv4
    expect_da = test.public_ipv4
    expect_len = -1
    pkt = IP(dst=str(test.tayga_ipv4), src=str(test.public_ipv4), proto=16) / Raw(randbytes(128))
    test.send_and_check(pkt, ip_val, "iter 5c: v4 icmp proto unreach")
    send_v6_rejected(map_v6+2,       "iter 5c: v6 absent")

    # iter 6a/b: v6 entry is within pref64
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None

    # map file: [1->1, 2->pref64]
    test.tayga_conf.map_file_entries = [
        f"{map_v4+1} {map_v6+1}",
        f"{map_v4+2} 3fff:6464::69",
    ]
    test.reload()

    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 6a: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 6a: v6 1->1 present")
    #[2->pref64] should not exist at all
    send_v4_rejected(map_v4+2,         "iter 6a: v4 2 absent")
    pkt = IPv6(dst="3fff:6464::69", src=str(test.public_ipv6), nh=16) / Raw(randbytes(128))
    test.send_and_none(pkt, "iter 6a: v6 pref64 absent")

    #Now, force reconf via SIGHUP and verify it has not modified behavior 
    test.reconf()
    #[1->1] has no conflict and should load correctly
    send_v4_mapped(map_v4+1, map_v6+1, "iter 6b: v4 1->1 present")
    send_v6_mapped(map_v6+1, map_v4+1, "iter 6b: v6 1->1 present")
    #[2->pref64] should not exist at all
    send_v4_rejected(map_v4+2,         "iter 6b: v4 2 absent")
    pkt = IPv6(dst="3fff:6464::69", src=str(test.public_ipv6), nh=16) / Raw(randbytes(128))
    test.send_and_none(pkt, "iter 6a: v6 pref64 absent")

    # Overlapping with dynamic-pool is not guaranteed at this point
    test.tfail("Map-file overlaps with dynamic-pool","Not Implemented")
    
    test.section("Map-File: Conflicts")


# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.2
test.setup()

#Test cases
test_reloading()
test_conflicts()

#Cleanup and test report
time.sleep(1)
test.cleanup()
test.report(144,1)