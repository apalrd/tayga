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
# Checksum Offload Testing
#############################################
def csum_offload():
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

class tcp_session_test:
    def __init__(self, test, name,port=0, chunk_size=512,xfr_size=512,timeout=1.0):
        self.test = test
        self.port = port
        self.name = name
        self.chunk_size = chunk_size
        self.xfr_size = xfr_size
        self.timeout = timeout
        self.server_socket = None
        self.client_socket = None
        self.local_addr = None
        self.server_addr = "::"
        self.client_addr = None
        self.bytes_recv = 0
        self.bytes_sent = 0
        self.running = False
    
    def _handle_connection(self):
        """Handle incoming connection and exchange data."""
        try:
            conn, addr = self.server_socket.accept()
            print(f"Connection accepted from {addr}")
            
            while self.running:
                data = os.urandom(self.chunk_size)
                try:
                    conn.sendall(data)
                    self.bytes_sent += len(data)
                    if(self.bytes_sent >= self.xfr_size): break
                except (BrokenPipeError, ConnectionResetError):
                    self.test.tfail(self.name,"Server Connection Reset")
                    break
            conn.close()
        except Exception as e:
            self.test.tfail(self.name,f"Server Handler Error {e}")
    
    def run(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_addr, self.port))
        self.server_socket.listen(1)
        if self.test.debug: print(f"Server listening on [{self.server_addr}]:{self.port}")
        
        # Start server handler thread
        self.server_thread = threading.Thread(target=self._handle_connection, daemon=True)
        self.server_thread.start()
        
        # Start client blocking
        time.sleep(0.01) # Give server time to start
        try:
            self.client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.client_socket.settimeout(self.timeout)
            if self.local_addr is not None: 
                self.client_socket.bind((self.local_addr,self.port+1))
                if self.test.debug: print(f"Client bound to [{self.local_addr}]:{self.port+1}")
            if self.test.debug: print(f"Connecting to server at [{self.client_addr}]:{self.port}")
            self.client_socket.connect((self.client_addr,self.port,0,0))
            
            while self.running:
                try:
                    data = self.client_socket.recv(self.chunk_size)
                    if not data:
                        self.test.tfail(self.name,"Client Read Error")
                        break
                    self.bytes_recv += len(data)
                    if(self.bytes_recv >= self.xfr_size): break
                except (ConnectionResetError, ConnectionAbortedError):
                    self.test.tfail(self.name,"Client Connection Reset")
                    break
            
            self.client_socket.close()
        except Exception as e:
            self.test.tfail(self.name,f"Client Error {e}")
        
        #Clean up test
        self.running = False
        self.server_thread.join(timeout=1)
        #Close sockets
        self.server_socket.close()
        self.client_socket.close()
        #Ensure we sent and received the right number of bytes
        if(self.bytes_sent >= self.xfr_size and self.bytes_recv >= self.xfr_size ): self.test.tpass(self.name)
        elif (self.bytes_sent < self.xfr_size): self.test.tfail(self.name,f"Sent {self.bytes_sent} out of {self.xfr_size}")
        else: self.test.tfail(self.name,f"Received {self.bytes_recv} out of {self.xfr_size}")



#############################################
# TCP Segment Offload (TSO) testing
#############################################
def tcp_seg():
    # Setup TCP test for a variety of sizes
    port = 666
    for size in [512, 1024, 2048, 4096, 65536, 1048576]:
        #Start a TCP session from v6 to v4
        port += 2
        tcp6 = tcp_session_test(test,f"TCP 6->4 size {size}",port=port,chunk_size=size,xfr_size=size*4)
        tcp6.client_addr = str(test.test_sys_ipv4_xlate)
        tcp6.local_addr = str(test.test_sys_ipv6)
        tcp6.server_addr = str(test.test_sys_ipv4.ipv6_mapped)
        tcp6.run()

        #Now do the same for v4
        port += 2
        tcp4 = tcp_session_test(test,f"TCP 4->6 size {size}",port=port,chunk_size=size,xfr_size=size*4)
        tcp4.client_addr = str(test.test_sys_ipv6_xlate.ipv6_mapped)
        tcp4.local_addr = str(test.test_sys_ipv4.ipv6_mapped)
        tcp4.server_addr = str(test.test_sys_ipv6)
        tcp4.run()

    test.section("TCP Segment Offload")

# Test was created at top of file
# Setup, call tests, etc.

test.debug = True
test.timeout = 0.1
test.setup()

# Call all tests
#csum_offload()
#multiqueue()
tcp_seg()

time.sleep(1)
test.cleanup()
#Print test report
test.report(0,0)