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
import socket

class route_dest(Enum):
    ROUTE_NORMAL = 0 # route to Tayga
    ROUTE_TEST = 1 #route to test system
    ROUTE_BLACKHOLE = 2
    ROUTE_UNREACHABLE = 3
    ROUTE_ADMIN_PROHIBIT = 4
    ROUTE_THROW = 5    

ipr = IPRoute()

class router:
    def __init__(self, route: str,dest: route_dest = route_dest.ROUTE_NORMAL):
        self.dest = dest
        self.route = ipaddress.ip_network(route)
        self.debug = False
        self.active = False

    def __del__(self):
        if self.active: self.remove()

    def apply(self):
        self.active = True
        try:
            if self.dest == route_dest.ROUTE_BLACKHOLE:
                ipr.route("add", dst=str(self.route), type="blackhole")
            elif self.dest == route_dest.ROUTE_UNREACHABLE:
                ipr.route("add", dst=str(self.route), type="unreachable")
            elif self.dest == route_dest.ROUTE_ADMIN_PROHIBIT:
                ipr.route("add", dst=str(self.route), type="prohibit")
            elif self.dest == route_dest.ROUTE_THROW:
                ipr.route("add", dst=str(self.route), type="throw")
            elif self.dest == route_dest.ROUTE_TEST:
                ipr.route("add", dst=str(self.route), oif=ipr.link_lookup(ifname="tun0")[0])            
            else:
                ipr.route("add", dst=str(self.route), oif=ipr.link_lookup(ifname="nat64")[0])            
        except Exception as e:
            print(f"Failed to add route to {self.route}: {e}")
            self.active = False
        if self.debug:
            print(f"Added route to {self.route}")
    
    def remove(self):
        self.active = False
        try:
            ipr.route("del", dst=str(self.route))
        except Exception as e:
            print(f"Failed to remove route to {self.route}: {e}")
        if self.debug:
            print(f"Removed route to {self.route}")

class test_res(Enum):
    RES_NONE = 0
    RES_PASS = 1
    RES_FAIL = 2

class single_res():
    def __init__(self,res:test_res,msg:str):
        self.res = res
        self.msg = msg

class test_result:
    def __init__(self):
        self.has_fail = False
        self.res = []

    def check(self,msg,condition):
        if not condition:
            self.has_fail = True
        self.res.append(single_res((test_res.RES_PASS if condition else test_res.RES_FAIL),msg))


    def compare(self,msg,left,right,print=True):
        if(left != right):
            self.has_fail = True
            if print:
                self.res.append(single_res(test_res.RES_FAIL,(msg+": got ("+str(left)+") expected ("+str(right)+")")))
            else:
                self.res.append(single_res(test_res.RES_FAIL,(msg+": got (<too long>) expected (<too long>)")))

        else:
            self.res.append(single_res(test_res.RES_PASS,msg))

    def failed(self):
        failures = sum(1 for result in self.res if result.res is test_res.RES_FAIL)
        return (failures > 0)

    def result(self):
        results = len(self.res)
        failures = sum(1 for result in self.res if result.res == test_res.RES_FAIL)
        if results == 0:
            return test_res.RES_NONE
        elif failures > 0:
            return test_res.RES_FAIL
        return test_res.RES_PASS
    
    def error(self):
        err = []
        for result in self.res:
            if result.res == test_res.RES_FAIL:
                err.append(result.msg)
        return ','.join(err)
    
#Tayga conf file generator
class confgen:
    def __init__(self):
        self.default()

    def default(self):
        self.device= "nat64"
        self.ipv4_addr = "172.16.0.3"
        self.ipv6_addr = None
        self.prefix = "3fff:6464::/96"
        self.wkpf_strict = False
        self.dynamic_pool = "172.16.0.0/24"
        self.data_dir = None
        self.map = []
        self.map.append("172.16.0.1 2001:db8::1")
        self.map.append("172.16.0.2 2001:db8::2")
        self.log = "drop reject icmp self"

    def generate(self):
        with open("test/tayga.conf", 'w') as conf_file:
            conf_file.write("tun-device "+self.device+"\n")
            conf_file.write("ipv4-addr "+self.ipv4_addr+"\n")
            if self.ipv6_addr is not None:
                conf_file.write("ipv6-addr "+self.ipv6_addr+"\n")
            conf_file.write("prefix "+self.prefix+"\n")
            if self.wkpf_strict:
                conf_file.write("wkpf-strict yes\n")
            else:
                conf_file.write("wkpf-strict no\n")
            if self.dynamic_pool is not None:
                conf_file.write("dynamic-pool "+self.dynamic_pool+"\n")
            if self.data_dir is not None:
                conf_file.write("data-dir "+self.data_dir+"\n")
            for entry in self.map:
                conf_file.write("map "+entry+"\n")
            if self.log is not None:
                conf_file.write("log "+self.log+"\n")



class test_env:
    def cleanup(self):
        print("Stopping Tayga")
        
        # Kill tcpdump process using the subprocess object
        if hasattr(self, 'tcpdump_proc') and self.tcpdump_proc:
            time.sleep(0.5) #Let TCPdump finish packets in transit
            try:
                self.tcpdump_proc.terminate()
                self.tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tcpdump_proc.kill()
                print("Tcpdump process did not terminate gracefully, force killed")

        # Kill Tayga process using the subprocess object
        if hasattr(self, 'tayga_proc') and self.tayga_proc:
            try:
                self.tayga_proc.terminate()
                self.tayga_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tayga_proc.kill()
                print("Tayga process did not terminate gracefully, force killed")
        else:
            if self.debug:
                print("Tayga process not found, skipping process termination")

        #Close tayga log file
        if hasattr(self, 'tayga_log') and self.tayga_log is not None:
            self.tayga_log.close()

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
        if self.debug:
            print("Bringing up the NAT64 interface")
        # Bring Up Interface
        try:
            self.tayga_conf.generate()
            subprocess.run([self.tayga_bin, "-c", self.tayga_conf_file, "-d", "--mktun"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error while bringing up interface: {e}")
        # Set NAT64 interface up
        ifi = ipr.link_lookup(ifname='nat64')[0]
        ipr.link('set', index=ifi, state='up')
        ipr.link("set", index=ifi, mtu=self.mtu)
        # Add IPv4 address to NAT64 interface
        ipr.addr('add', index=ifi, address=str(self.tayga_pool4.network_address), mask=self.tayga_pool4.prefixlen)
        # Add IPv6 address to NAT64 interface
        ipr.route('add', dst=str(self.tayga_prefix), oif=ifi)

    def setup_tcpdump(self):
        iface = "nat64"
        if self.pcap_test_env:
            iface = "tun0"
        # If tcpdump file variable is set, start tcpdump
        if self.pcap_file:
            print("Starting tcpdump for interface "+iface)
            self.tcpdump_proc = subprocess.Popen(
                ["tcpdump", "-i", iface, "-w", self.pcap_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2)

    def setup_tayga(self):
        # Generate configl
        self.tayga_conf.generate()
        print("Starting Tayga")
        # Start Tayga asynchronously and capture output to a file if specified
        if self.tayga_log_file and not hasattr(self, 'tayga_log'):
            try:
                self.tayga_log = open(self.tayga_log_file, "w")
            except OSError as e:
                print(f"Error while opening output file: {e}")
                sys.exit(1)
        elif not hasattr(self, "tayga_log"):
            self.tayga_log = None

        try:
            new_args = ["-c",self.tayga_conf_file,"-d"]
            total_args = []
            if self.use_valgrind:
                #Append valgrind command
                total_args.extend(self.valgrind_opts)
            # Append Tayga command
            total_args.append(self.tayga_bin)
            # Append args to Tayga
            total_args.extend(new_args)
            self.tayga_proc = subprocess.Popen(
            total_args,
            stdout=self.tayga_log if self.tayga_log else subprocess.DEVNULL,
            stderr=subprocess.STDOUT
            )
        except subprocess.SubprocessError as e:
            print(f"Error while starting Tayga: {e}")
            if self.tayga_log:
                self.tayga_log.close()
            sys.exit(1)

        # Wait for a short time to ensure Tayga starts
        time.sleep(1)

        # Check if Tayga started successfully
        if self.tayga_proc.poll() is not None:  # Check if the process has already terminated
            print("Tayga failed to start")
            sys.exit(1)

    def setup_tun(self):
        print(f"Creating TUN/TAP interface")
        # Create a TUN/TAP interface
        tun = TunTapInterface(iface="tun0", mode_tun=True, strip_packet_info=False)
        tun_index = ipr.link_lookup(ifname="tun0")[0]
        ipr.link("set", index=tun_index, state="up")
        ipr.link("set", index=tun_index, mtu=self.mtu)
        ipr.addr("add", index=tun_index, address=str(self.test_sys_ipv4), mask=24)
        ipr.addr("add", index=tun_index, address=str(self.test_sys_ipv6), mask=64)
        ipr.route("add",dst="default",oif=tun_index)
        ipr.route("add",dst="::/0",oif=tun_index,family=socket.AF_INET6)
        self.tun = tun


    def __init__(self,test_name):
        #These are the default values for the test environment
        self.debug = False
        self.tayga_bin = "./tayga"
        self.mtu = 1500
        self.tayga_pool4 = ipaddress.ip_network("172.16.0.0/24")
        self.tayga_prefix = ipaddress.ip_network("3fff:6464::/96")
        self.public_ipv4 = ipaddress.ip_address("192.168.1.2")
        self.public_ipv4_xlate = ipaddress.ip_address("3fff:6464::192.168.1.2")
        self.public_ipv6 = ipaddress.ip_address("2001:db8::2")
        self.public_ipv6_xlate = ipaddress.ip_address("172.16.0.2")
        self.test_sys_ipv4 = ipaddress.ip_address("192.168.1.1")
        self.test_sys_ipv4_xlate = ipaddress.ip_address("3fff:6464::192.168.1.1")
        self.test_sys_ipv6 = ipaddress.ip_address("2001:db8::1")
        self.test_sys_ipv6_xlate = ipaddress.ip_address("172.16.0.1")
        self.icmp_router_ipv4 = ipaddress.ip_address("203.0.113.1")
        self.icmp_router_ipv6 = ipaddress.ip_address("2001:db8:f00f::1")
        self.tayga_ipv4 = ipaddress.ip_address("172.16.0.3")
        self.tayga_ipv6 = ipaddress.ip_address("3fff:6464::172.16.0.3")
        self.tayga_conf_file = "test/tayga.conf"
        self.pcap_file = test_name + ".pcap"
        self.pcap_test_env = False
        self.tayga_log_file = test_name + ".log"
        self.test_name = test_name
        self.file_path = test_name + ".rpt"
        self.test_results = []
        self.test_passed = 0
        self.test_failed = 0
        self.timeout = 1 # seconds
        self.tayga_conf = confgen()
        # Valgrind
        self.use_valgrind = False
        self.valgrind_opts = ["valgrind", "--tool=callgrind","--dump-instr=yes","--simulate-cache=yes","--collect-jumps=yes"]

        # write report header
        with open(self.file_path, 'w') as report_file:
            report_file.write("Test Report "+self.test_name+"\n")
            report_file.write("=" * 40 + "\n")
            print("Starting Test Report for "+self.test_name)
            print("="*40)


    def setup(self):
        # Register the teardown function to run on exit
        atexit.register(self.cleanup)
        # Setup the test environment
        self.setup_forward()
        self.setup_nat64()
        self.setup_tayga()
        self.setup_tun()
        self.setup_tcpdump()

    def reload(self):
        print("Restarting Tayga with new configuration")
        # Kill Tayga process using the subprocess object
        if hasattr(self, 'tayga_proc') and self.tayga_proc:
            try:
                self.tayga_proc.terminate()
                self.tayga_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tayga_proc.kill()
                print("Tayga process did not terminate gracefully, force killed")
        else:
            if self.debug:
                print("Tayga process not found, skipping process termination")

        # Reset link MTU
        ifi = ipr.link_lookup(ifname='nat64')[0]
        ipr.link("set", index=ifi, mtu=self.mtu)
        ifi = ipr.link_lookup(ifname='tun0')[0]
        ipr.link("set", index=ifi, mtu=self.mtu)
        # Regenerate the conf file and restart
        self.setup_tayga()

    def xlate(self, ipv4, prefix = None):
        if prefix is None:
            prefix = str(self.tayga_prefix.network_address)
        return str(ipaddress.ip_address(prefix + str(ipaddress.ip_address(ipv4))))

    def flush(self):
        # Use the sniff method for 0.1 seconds
        self.tun.sniff(timeout=0.1,store=False)


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

    def _val_snd_check(self,pkt):
        # Toss link-local packets since we shouldn't see them on our
        # tun adapter
        if pkt.haslayer(IPv6):
            if ipaddress.IPv6Address(pkt[IPv6].src).is_link_local:
                return False
            if ipaddress.IPv6Address(pkt[IPv6].dst).is_link_local:
                return False
        # Toss IPv4 IGMP
        if pkt.haslayer(IP):
            if pkt[IP].proto == 2:
                return False
        # Toss LLMNR
        if pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.252":
            return False
        # Check if the received packet matches the expected response
        try:
            res = self.response_func(pkt)
        except Exception as e:
            print(f"Exception occurred while processing packet in {self.test_name}: {e}")
            print(pkt.show())
            return False
        if res.result() != test_res.RES_NONE:
            if self.debug or res.has_fail:
                print(f"Received packet matching {self.test_name}")
                print(pkt.show())
            self.test_stat = res
            return True
        return False

    def send_and_check(self,packet,response_func,test_name):
        self.test_name = test_name
        self.response_func = response_func
        self.test_stat = test_result()

        # Send the packet using the test.tun interface
        if self.debug:
            print(f"Sending packet for {test_name}:")
            print(packet.show())
        # Send the packet
        self.tun.send(packet)

        # Use the sniff method to wait for a response
        self.tun.sniff(timeout=self.timeout,stop_filter=self._val_snd_check,store=False)

        if self.test_stat.result() == test_res.RES_NONE:
            self.tfail(self.test_name,"No valid response received")
        elif self.test_stat.result() == test_res.RES_FAIL:
            self.tfail(self.test_name,self.test_stat.error())
        else:
            self.tpass(self.test_name)

    def _val_snd_check2(self,pkt):
        # Toss link-local packets since we shouldn't see them on our
        # tun adapter
        if pkt.haslayer(IPv6):
            if ipaddress.IPv6Address(pkt[IPv6].src).is_link_local:
                return False
            if ipaddress.IPv6Address(pkt[IPv6].dst).is_link_local:
                return False
        # Toss IPv4 IGMP
        if pkt.haslayer(IP):
            if pkt[IP].proto == 2:
                return False
        # Toss LLMNR
        if pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.252":
            return False
        # Check if the received packet matches the expected response
        try:
            if self.first_pkt: res = self.response_func(pkt)
            else: res = self.response_func2(pkt)
        except Exception as e:
            print(f"Exception occurred while processing packet in {self.test_name}: {e}")
            print(pkt.show())
            return False
        if res.result() != test_res.RES_NONE:
            if self.debug or res.has_fail:
                print(f"Received packet matching {self.test_name}")
                print(pkt.show())
            if self.first_pkt:
                self.test_stat = res
                self.first_pkt = False
                return False
            else: 
                self.test_stat2 = res
                return True
        return False

    def send_and_check_two(self,packet,response_func,response_func2,test_name):
        self.test_name = test_name
        self.response_func = response_func
        self.response_func2 = response_func2
        self.test_stat = test_result()
        self.test_stat2 = test_result()
        self.first_pkt = True

        # Send the packet using the test.tun interface
        if self.debug:
            print(f"Sending packet for {test_name}:")
            print(packet.show())
        # Send the packet
        self.tun.send(packet)

        # Use the sniff method to wait for a response
        self.tun.sniff(timeout=self.timeout,stop_filter=self._val_snd_check2,store=False)

        # First Result
        if self.test_stat.result() == test_res.RES_NONE:
            self.tfail(self.test_name+" Pkt1","No valid response received")
        elif self.test_stat.result() == test_res.RES_FAIL:
            self.tfail(self.test_name+" Pkt1",self.test_stat.error())
        else:
            self.tpass(self.test_name+" Pkt1")

        # Second Result
        if self.test_stat2.result() == test_res.RES_NONE:
            self.tfail(self.test_name+" Pkt2","No valid response received")
        elif self.test_stat2.result() == test_res.RES_FAIL:
            self.tfail(self.test_name+" Pkt2",self.test_stat2.error())
        else:
            self.tpass(self.test_name+" Pkt2")

    def _val_snd_none(self,pkt):
        #If the packet is IPv6 link-local src or dest, toss it
        if pkt.haslayer(IPv6):
            if ipaddress.IPv6Address(pkt[IPv6].src).is_link_local:
                return False
            if ipaddress.IPv6Address(pkt[IPv6].dst).is_link_local:
                return False
        # Toss IPv4 IGMP
        if pkt.haslayer(IP):
            if pkt[IP].proto == 2:
                return False
        # Toss LLMNR
        if pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.252":
            return False
        # Got an unexpected packet
        print(f"Received unexpected packet for {self.test_name}")
        if self.debug:
            print(pkt.show())
        self.test_stat = False
        return True

    def send_and_none(self,packet,test_name):
        self.test_name = test_name
        self.test_stat = True #default pass, unless we get an odd one
        self.test_err = "Unexpected Packet Received"

        # Send the packet using the tun interface
        if self.debug:
            print(f"Sending packet for {test_name}:")
            print(packet.show())
        # Send the packet
        self.tun.send(packet)

        # Use the sniff method to wait for a response
        self.tun.sniff(timeout=self.timeout,stop_filter=self._val_snd_none,store=False)

        if self.test_stat:
            self.tpass(self.test_name)
        else:
            print("Failing Test "+self.test_name)
            self.tfail(self.test_name, self.test_err)