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
# Test 1: Reloading
#
# Each iteration writes a new map file, reloads, then probes all three
# address pairs (+0, +1, +2) to verify what is and isn't mapped.
# The sequence exercises every overlap branch in addrmap_entry/addrmap_reload:
#
#   startup   [1->1, 2->2]          initial load, both new (!m4 && !m6)
#   iter 1    [1->1, 2->2]          no-op (n1==n2, line_no refresh only)
#   iter 2    [1->1, 2->2, 3->3]    add entry 3 (!m4 && !m6)
#   iter 3    [1->1, 3->3]          delete entry 2
#   iter 4    [1->3, 3->3]          update IPv6 side of 1 (m4-only conflict)
#   iter 5    [3->1, 3->3]          update IPv4 side (m6-only conflict)
#   iter 6    [1->3]                collapse two entries into one (n1!=n2)
#   iter 7    []                    remove all entries
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

    return
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

    return

    # iter 4: [0->2, 3->3] — update IPv6 side of entry 0 (m4-only conflict)
    # v4+0 was mapped to v6+0; now mapped to v6+2 which is already taken by entry 2
    test.tayga_conf.map_file_entries = [
        f"{map_v4+0} {map_v6+2}",
        f"{map_v4+2} {map_v6+2}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+0, map_v6+2, "iter 4: v4+0->v6+2 present")
    send_v6_mapped(map_v6+2, map_v4+0, "iter 4: v6+2->v4+0 present")
    send_v4_rejected(map_v4+1,                   "iter 4: v4+1 absent")
    send_v4_rejected(map_v4+2,                   "iter 4: v4+2 absent")
    send_v6_rejected(map_v6+0,                   "iter 4: v6+0 absent")
    send_v6_rejected(map_v6+1,                   "iter 4: v6+1 absent")

    # iter 5: [2->0, 3->3] — update IPv4 side (m6-only conflict)
    # v6+2 was mapped from v4+0; now mapped from v4+2 which is already taken
    test.tayga_conf.map_file_entries = [
        f"{map_v4+2} {map_v6+0}",
        f"{map_v4+2} {map_v6+2}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+2, map_v6+0, "iter 5: v4+2->v6+0 present")
    send_v6_mapped(map_v6+0, map_v4+2, "iter 5: v6+0->v4+2 present")
    send_v4_rejected(map_v4+0,                   "iter 5: v4+0 absent")
    send_v4_rejected(map_v4+1,                   "iter 5: v4+1 absent")
    send_v6_rejected(map_v6+1,                   "iter 5: v6+1 absent")
    send_v6_rejected(map_v6+2,                   "iter 5: v6+2 absent")

    # iter 6: [0->2] — v4+0 conflicts with nothing on v4, v6+2 conflicts with
    # the existing entry on v6; two different containers (n1!=n2)
    test.tayga_conf.map_file_entries = [
        f"{map_v4+0} {map_v6+2}",
    ]
    test.reconf()
    send_v4_mapped(map_v4+0, map_v6+2, "iter 6: v4+0->v6+2 present")
    send_v6_mapped(map_v6+2, map_v4+0, "iter 6: v6+2->v4+0 present")
    send_v4_rejected(map_v4+1,                   "iter 6: v4+1 absent")
    send_v4_rejected(map_v4+2,                   "iter 6: v4+2 absent")
    send_v6_rejected(map_v6+0,                   "iter 6: v6+0 absent")
    send_v6_rejected(map_v6+1,                   "iter 6: v6+1 absent")

    # iter 7: [] — empty file removes last entry
    test.tayga_conf.map_file_entries = []
    test.reconf()
    send_v4_rejected(map_v4+0, "iter 7: v4+0 absent")
    send_v4_rejected(map_v4+1, "iter 7: v4+1 absent")
    send_v4_rejected(map_v4+2, "iter 7: v4+2 absent")
    send_v6_rejected(map_v6+0, "iter 7: v6+0 absent")
    send_v6_rejected(map_v6+1, "iter 7: v6+1 absent")
    send_v6_rejected(map_v6+2, "iter 7: v6+2 absent")

    test.section("Map-File: Reloading")


# ---------------------------------------------------------------------------
# Test 2: Conflicts
#
# 2a. Map-file entry conflicts with a conf-file static entry: conf wins,
#     both at startup and after SIGHUP.
# 2b. Map-file entry conflicts with a dynamic pool address: rejected,
#     both at startup and after SIGHUP; pool continues to function.
# ---------------------------------------------------------------------------
def test_conflicts():
    # --- 2a: conflict with conf-file static entry ---
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None
    test.tayga_conf.map.append(f"{test.public_ipv4+0} {test.public_ipv6+0}")
    test.tayga_conf.map_file_entries = [f"{test.public_ipv4+0} {test.public_ipv6+1}"]
    test.reload()

    send_v4_mapped(test.public_ipv4+0, test.public_ipv6+0, "conf conflict: conf entry wins at startup")
    send_v6_rejected(test.public_ipv6+1,                   "conf conflict: map-file target absent at startup")

    test.reconf()

    send_v4_mapped(test.public_ipv4+0, test.public_ipv6+0, "conf conflict: conf entry still wins after SIGHUP")
    send_v6_rejected(test.public_ipv6+1,                   "conf conflict: map-file target still absent after SIGHUP")

    # --- 2b: conflict with dynamic pool address ---
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = "169.254.0.0/24"
    pool_v4 = ipaddress.ip_address("169.254.0.50")
    test.tayga_conf.map_file_entries = [f"{pool_v4} {test.public_ipv6+0}"]
    test.reload()

    global expect_sa, expect_da, expect_len, expect_proto, expect_data

    def pool_val(pkt):
        res = test_result()
        res.check("Contains IPv4", isinstance(pkt.getlayer(1), IP))
        if res.has_fail:
            return res
        res.compare("Proto", pkt[IP].proto, 16)
        res.check("Src in pool",
                  ipaddress.ip_address(pkt[IP].src)
                  in ipaddress.ip_network("169.254.0.0/24"))
        res.compare("Dest", pkt[IP].dst, str(test.public_ipv4))
        return res

    pkt = IPv6(dst=str(test.public_ipv4_xlate),
               src=str(test.public_ipv6), nh=16) / Raw(randbytes(128))
    test.send_and_check(pkt, pool_val,
                        "pool conflict: dynamic pool allocates at startup")

    send_v6_rejected(test.public_ipv6+0, "pool conflict: map-file entry rejected at startup")

    test.reconf()

    pkt = IPv6(dst=str(test.public_ipv4_xlate),
               src=str(test.public_ipv6), nh=16) / Raw(randbytes(128))
    test.send_and_check(pkt, pool_val,
                        "pool conflict: dynamic pool still allocates after SIGHUP")

    send_v6_rejected(test.public_ipv6+0, "pool conflict: map-file entry still rejected after SIGHUP")

    test.section("Map-File: Conflicts")


# ---------------------------------------------------------------------------
# Test 3: File handling
#
# 3a. Empty file at startup: no entries, SIGHUP clears nothing, RFC6052 works.
# 3b. No map-file directive: reconf() sends SIGHUP with no file configured,
#     RFC6052 continues to work.
# ---------------------------------------------------------------------------
def test_file_handling():
    # --- 3a: empty file ---
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None
    test.tayga_conf.map_file_entries = []
    test.reload()

    send_v4_rejected(test.public_ipv4+0, "empty file: no entries at startup")

    test.reconf()

    send_v4_rejected(test.public_ipv4+0, "empty file: still no entries after SIGHUP")

    # --- 3b: no map-file directive ---
    test.flush()
    test.tayga_conf.default()
    test.tayga_conf.dynamic_pool = None
    # map_file_entries defaults to [] — no file written, no directive emitted
    test.reload()

    global expect_sa, expect_da, expect_len, expect_proto, expect_data
    expect_proto = 16
    expect_len   = 128
    expect_data  = randbytes(128)
    expect_sa    = test.public_ipv6_xlate
    expect_da    = test.xlate(str(test.public_ipv4+0))
    pkt = IP(dst=str(test.public_ipv4+0), src=str(test.public_ipv4), proto=16) / Raw(expect_data)
    test.send_and_check(pkt, ip6_val, "no map-file: RFC6052 works before SIGHUP")

    test.reconf()

    expect_data  = randbytes(128)
    expect_sa    = test.public_ipv6_xlate
    expect_da    = test.xlate(str(test.public_ipv4+0))
    pkt = IP(dst=str(test.public_ipv4+0), src=str(test.public_ipv4), proto=16) / Raw(expect_data)
    test.send_and_check(pkt, ip6_val, "no map-file: RFC6052 works after SIGHUP")

    test.section("Map-File: File Handling")


# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.2
test.setup()

#Test cases
test_reloading()
#test_conflicts()
#test_file_handling()

#Cleanup and test report
time.sleep(1)
test.cleanup()
test.report(58, 0)