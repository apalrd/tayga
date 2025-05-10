import os
import subprocess
import sys
from pyroute2 import IPRoute
import ipaddress
import atexit
import time
from scapy.layers.tuntap import TunTapInterface
from test_report import test_report

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
        self.PublicIPv6 = ipaddress.ip_address("2001:db8::2")
        self.TestSystemIPv4 = ipaddress.ip_address("192.168.1.1")
        self.TestSystemIPv4Xlate = ipaddress.ip_address("3fff:6464::192.168.1.1")
        self.TestSystemIPv6 = ipaddress.ip_address("2001:db8::1")
        self.TaygaConf = "test/tayga.conf"
        self.TcpdumpFile = None
        self.Fail = False
        self.file_path = test_name + ".rpt"
        self.test_results = []
        self.timeout = 1 # seconds


    def setup(self):
        # Setup the test environment
        self.setup_forward()
        self.setup_nat64()
        self.setup_tcpdump()
        self.start_tayga()
        self.setup_tun()
    
        # Register the teardown function to run on exit
        atexit.register(self.cleanup)

    def tpass(self, test_name):
        self.test_results.append(f"PASS: {test_name}")

    def tfail(self, test_name, reason):
        self.test_results.append(f"FAIL: {test_name} - {reason}")

    def report(self):
        with open(self.file_path, 'w') as report_file:
            report_file.write("Test Report\n")
            report_file.write("=" * 40 + "\n")
            for result in self.test_results:
                report_file.write(result + "\n")
            report_file.write("=" * 40 + "\n")
            report_file.write(f"Total Tests: {len(self.test_results)}\n")
            passed = sum(1 for result in self.test_results if result.startswith("PASS"))
            report_file.write(f"Passed: {passed}\n")
            report_file.write(f"Failed: {len(self.test_results) - passed}\n")

    # Send a packet and check for a suitable response
    def send_and_check(self,packet,response_func,test_name):
        # Send the packet using the test.tun interface
        self.tun.send(packet)

        end = time.perf_counter() + self.timeout
        test_stat = False
        while time.perf_counter() < end:
            response_packet = self.tun.recv()
            if response_func(response_packet):
                print(f"Received a valid response for {test_name}:")
                if self.debug:
                    print(response_packet.show())
                test_stat = True
                break

        if test_stat:
            self.tpass(test_name)
        else:
            self.tfail(test_name, "No valid response received")
        return not test_stat