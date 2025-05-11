import os
import subprocess
import sys
from pyroute2 import IPRoute
import ipaddress
import atexit
import time
from scapy.layers.tuntap import TunTapInterface
from scapy.all import IPv6, IP
from enum import Enum

class test_res(Enum):
    RES_NONE = 0
    RES_PASS = 1
    RES_FAIL = 2

class test_result:
    def __init__(self):
        self.has_result = False
        self.has_fail = False
        self.err = []

    def check(self,msg,condition):
        if(not condition):
            self.has_fail = True
            self.err.append(msg)
        self.has_result = True

    def compare(self,msg,left,right):
        if(left != right):
            self.has_fail = True
            self.err.append(msg+": got ("+str(left)+") expected ("+str(right)+")")
        self.has_result = True

    def result(self):
        if not self.has_result:
            return test_res.RES_NONE
        elif self.has_fail:
            return test_res.RES_FAIL
        return test_res.RES_PASS
    
    def error(self):
        return ','.join(self.err)


class test_env:
    def cleanup(self):
        print("Stopping Tayga")
        ipr = IPRoute()
        
        # Kill tcpdump process by PID file
        try:
            with open("/var/run/tcpdump.pid", "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 9)
            os.remove("/var/run/tcpdump.pid")
        except FileNotFoundError:
            if self.debug:
                print("Tcpdump PID file not found, skipping process termination")
        except ProcessLookupError:
            if self.debug:
                print("Tcpdump process not found, skipping process termination")

        # Kill Tayga process by PID file
        try:
            with open("/var/run/tayga.pid", "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 9)
            os.remove("/var/run/tayga.pid")
        except FileNotFoundError:
            if self.debug:
                print("Tayga PID file not found, skipping process termination")
        except ProcessLookupError:
            if self.debug:
                print("Tayga process not found, skipping process termination")

        # Remove the NAT64 interface
        try:
            ipr.link("del", ifname="nat64")
        except Exception as e:
            if self.debug:
                print(f"Failed to delete NAT64 interface: {e}")

        atexit.unregister(self.cleanup)


    def setup_forward(self):
        # Enable IP Forwarding
        if self.debug:
            print("Enabling IPv4 and IPv6 forwarding")
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"], check=True)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True)

    def setup_nat64(self):
        ipr = IPRoute()
        if self.debug:
            print("Bringing up the NAT64 interface")
        # Bring Up Interface
        try:
            subprocess.run([self.Tayga, "-c", self.TaygaConf, "-d", "--mktun"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while bringing up interface: {e}")
        # Set NAT64 interface up
        ipr.link('set', index=ipr.link_lookup(ifname='nat64')[0], state='up')
        # Add IPv4 address to NAT64 interface
        ipr.addr('add', index=ipr.link_lookup(ifname='nat64')[0], address=str(self.TaygaPool4.network_address), mask=self.TaygaPool4.prefixlen)
        # Add IPv6 address to NAT64 interface
        ipr.addr('add', index=ipr.link_lookup(ifname='nat64')[0], address=str(self.TaygaPrefix.network_address), mask=self.TaygaPrefix.prefixlen)

    def setup_tcpdump(self):
        # If tcpdump file variable is set, start tcpdump
        if self.TcpdumpFile:
            print("Starting tcpdump")
            tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "nat64", "-w", self.TcpdumpFile])
            with open("/var/run/tcpdump.pid", "w") as f:
                f.write(str(tcpdump_proc.pid))

    def start_tayga(self):
        # Start Tayga
        try:
            subprocess.run([self.Tayga, "-c", self.TaygaConf, "-p", "/var/run/tayga.pid"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while starting Tayga: {e}")

        # Check if Tayga started successfully
        if not os.path.isfile("/var/run/tayga.pid"):
            print("Tayga failed to start")
            sys.exit(1)

    def setup_tun(self):

        print(f"Creating TUN/TAP interface")
        # Create a TUN/TAP interface
        tun = TunTapInterface(iface="tun0", mode_tun=True, strip_packet_info=False)
        ipr = IPRoute()
        tun_index = ipr.link_lookup(ifname="tun0")[0]
        ipr.link("set", index=tun_index, state="up")
        ipr.addr("add", index=tun_index, address=str(self.TestSystemIPv4), mask=24)
        ipr.addr("add", index=tun_index, address=str(self.TestSystemIPv6), mask=64)
        ipr.link("set", index=tun_index, mtu=1500)
        self.tun = tun

    def __init__(self,test_name):
        #These are the default values for the test environment
        self.debug = False
        self.Tayga = "./tayga"
        self.TaygaPool4 = ipaddress.ip_network("172.16.0.0/24")
        self.TaygaPrefix = ipaddress.ip_network("3fff:6464::/96")
        self.PublicIPv4 = ipaddress.ip_address("192.168.1.2")
        self.PublicIPv4Xlate = ipaddress.ip_address("3fff:6464::192.168.1.2")
        self.PublicIPv6 = ipaddress.ip_address("2001:db8::2")
        self.PublicIPv6Xlate = ipaddress.ip_address("172.16.0.2")
        self.TestSystemIPv4 = ipaddress.ip_address("192.168.1.1")
        self.TestSystemIPv4Xlate = ipaddress.ip_address("3fff:6464::192.168.1.1")
        self.TestSystemIPv6 = ipaddress.ip_address("2001:db8::1")
        self.TestSystemIPv6Xlate = ipaddress.ip_address("172.16.0.1")
        self.IcmpRouterIPv4 = ipaddress.ip_address("203.0.113.1")
        self.IcmpRouterIPv6 = ipaddress.ip_address("2001:db8:f00f::1")
        self.TaygaConf = "test/tayga.conf"
        self.TcpdumpFile = None
        self.Fail = False
        self.test_name = test_name
        self.file_path = test_name + ".rpt"
        self.test_results = []
        self.test_passed = 0
        self.test_failed = 0
        self.timeout = 1 # seconds


    def setup(self):
        # Register the teardown function to run on exit
        atexit.register(self.cleanup)
        # Setup the test environment
        self.setup_forward()
        self.setup_nat64()
        self.setup_tcpdump()
        self.start_tayga()
        self.setup_tun()
        # write report header
        with open(self.file_path, 'w') as report_file:
            report_file.write("Test Report "+self.test_name+"\n")
            report_file.write("=" * 40 + "\n")
            print("Starting Test Report for "+self.test_name)
            print("="*40)


    def tpass(self, test_name):
        self.test_results.append(f"PASS: {test_name}")

    def tfail(self, test_name, reason):
        self.test_results.append(f"FAIL: {test_name} - {reason}")

    def section(self,sec_name):
        with open(self.file_path, 'a') as report_file:
            report_file.write("Test Section "+sec_name+"\n")
            print("Test Section "+sec_name)
            for result in self.test_results:
                report_file.write(result + "\n")
                print(result)
            report_file.write(f"Section Tests: {len(self.test_results)}\n")
            passed = sum(1 for result in self.test_results if result.startswith("PASS"))
            report_file.write(f"Passed: {passed}\n")
            report_file.write(f"Failed: {len(self.test_results) - passed}\n")
            report_file.write("=" * 40 + "\n")
            #Total test pass/fail counter
            self.test_passed += passed
            self.test_failed += len(self.test_results) - passed
            print(f"Section Tests: {len(self.test_results)}")
            print(f"Passed: {passed}")
            print(f"Failed: {len(self.test_results) - passed}")
        #Clear test results for next section
        self.test_results = []


    def report(self):
        # If we have any test results, finish this section
        if len(self.test_results) > 0:
            self.section("General")
        #Now write the termination
        with open(self.file_path, 'a') as report_file:
            report_file.write(f"Total Tests: {self.test_passed+self.test_failed}\n")
            report_file.write(f"Passed: {self.test_passed}\n")
            report_file.write(f"Failed: {self.test_failed}\n")
            print("="*40)
            print(f"Total Tests: {self.test_passed+self.test_failed}")
            print(f"Passed: {self.test_passed}")
            print(f"Failed: {self.test_failed}")

    # Send a packet and check for a suitable response

class send_and_check:
    def recv_validate(self,pkt):
        # Toss link-local packets since we shouldn't see them on our
        # tun adapter
        if pkt.haslayer(IPv6):
            if ipaddress.IPv6Address(pkt[IPv6].src).is_link_local:
                return False
            if ipaddress.IPv6Address(pkt[IPv6].dst).is_link_local:
                return False
        # Check if the received packet matches the expected response
        if self.test.debug:
            print(f"Received packet for {self.test_name}:")
            print(pkt.show())
        # Check if the received packet matches the expected response
        res = self.response_func(pkt)
        if res.result() != test_res.RES_NONE:
            if self.test.debug or res.has_fail:
                print(f"Received packet matching {self.test_name}")
            self.test_stat = res
            return True
        return False

    def __init__(self,test,packet,response_func,test_name):
        self.test = test
        self.test_name = test_name
        self.response_func = response_func
        self.test_stat = test_result()

        # Send the packet using the test.tun interface
        if self.test.debug:
            print(f"Sending packet for {test_name}:")
            print(packet.show())
        # Send the packet
        self.test.tun.send(packet)

        # Use the sniff method to wait for a response
        self.test.tun.sniff(timeout=self.test.timeout,stop_filter=self.recv_validate,store=False)

        if not self.test_stat.has_result:
            self.test.tfail(self.test_name,"No valid response received")
        elif self.test_stat.has_fail:
            self.test.tfail(self.test_name,self.test_stat.error())
        else:
            self.test.tpass(self.test_name)

    def failed(self):
        return not self.test_stat
    

class send_and_none:
    def recv_validate(self,pkt):
        #If the packet is IPv6 link-local src or dest, toss it
        if pkt.haslayer(IPv6):
            if ipaddress.IPv6Address(pkt[IPv6].src).is_link_local:
                return False
            if ipaddress.IPv6Address(pkt[IPv6].dst).is_link_local:
                return False
        # Check if the received packet matches the expected response
        if self.test.debug:
            print(f"Received packet for {self.test_name}:")
            print(pkt.show())
        # Got an unexpected packet
        print(f"Received unexpected packet for {self.test_name}:")
        print(pkt.show())
        self.test_state = False
        return True

    def __init__(self,test,packet,test_name):
        self.test = test
        self.test_name = test_name
        self.test_stat = True #default pass, unless we get an odd one
        self.test_err = "Unexpected Packet Received"

        # Send the packet using the test.tun interface
        if self.test.debug:
            print(f"Sending packet for {test_name}:")
            print(packet.show())
        # Send the packet
        self.test.tun.send(packet)

        # Use the sniff method to wait for a response
        self.test.tun.sniff(timeout=self.test.timeout,stop_filter=self.recv_validate,store=False)

        if self.test_stat:
            self.test.tpass(self.test_name)
        else:
            self.test.tfail(self.test_name, self.test_err)

    def failed(self):
        return not self.test_stat