#!/usr/bin/env python3
from scapy.all import IP, TCP, UDP, ICMP, send, RandIP, Raw, get_if_addr
import time
import random
import argparse
import os
from tqdm import tqdm

def check_root():
    """Check if the script is running with root privileges"""
    if os.geteuid() != 0:
        raise PermissionError(
            "This script requires root privileges to send network packets.\n"
            "Please run it with sudo: sudo python3 -m ids.generate_suspicious_traffic"
        )

def get_network_info(interface='eth0'):
    """Get network information for the specified interface"""
    try:
        ip = get_if_addr(interface)
        return ip
    except:
        print(f"[!] Error: Could not get IP address for interface {interface}")
        return None

class SuspiciousTrafficGenerator:
    def __init__(self, target_ip, interface='eth0'):
        check_root()
        self.target_ip = target_ip
        self.interface = interface
        self.source_ip = get_network_info(interface)
        if not self.source_ip:
            raise ValueError(f"Could not get IP address for interface {interface}")
        print(f"[*] Using source IP: {self.source_ip}")
        
    def generate_port_scan(self, num_ports=1000):
        """Generate a port scanning attack"""
        print(f"\n[*] Starting port scan attack against {self.target_ip}")
        ports = random.sample(range(1, 65536), num_ports)
        src_port = random.randint(1024, 65535)
        
        with tqdm(total=num_ports, desc="Port scanning") as pbar:
            for port in ports:
                # SYN scan
                packet = IP(src=self.source_ip, dst=self.target_ip)/TCP(sport=src_port, dport=port, flags="S")
                send(packet, verbose=False, iface=self.interface)
                pbar.update(1)
                time.sleep(0.001)  # Faster scanning

    def generate_ddos(self, duration=5, intensity=100):
        """Generate a DDoS attack simulation"""
        print(f"\n[*] Starting DDoS attack simulation against {self.target_ip}")
        start_time = time.time()
        packets_sent = 0
        
        with tqdm(total=duration*intensity, desc="DDoS attack") as pbar:
            while time.time() - start_time < duration:
                for _ in range(intensity):
                    # Mix of UDP flood and HTTP flood
                    if random.random() < 0.5:
                        # UDP flood
                        packet = IP(src=self.source_ip, dst=self.target_ip)/UDP(
                            sport=random.randint(1024, 65535),
                            dport=random.randint(1, 65535)
                        )/Raw(load="X"*random.randint(64, 1400))
                    else:
                        # HTTP flood
                        packet = IP(src=self.source_ip, dst=self.target_ip)/TCP(
                            sport=random.randint(1024, 65535),
                            dport=80,
                            flags="S"
                        )/Raw(load="GET / HTTP/1.1\r\nHost: target\r\n\r\n")
                    
                    send(packet, verbose=False, iface=self.interface)
                    packets_sent += 1
                    pbar.update(1)
                time.sleep(0.001)
        
        print(f"Sent {packets_sent} DDoS packets")

    def generate_ping_flood(self, count=500):
        """Generate a ping flood attack"""
        print(f"\n[*] Starting ping flood against {self.target_ip}")
        with tqdm(total=count, desc="Ping flood") as pbar:
            for _ in range(count):
                packet = IP(src=self.source_ip, dst=self.target_ip)/ICMP()
                send(packet, verbose=False, iface=self.interface)
                pbar.update(1)
                time.sleep(0.001)

    def generate_syn_flood(self, duration=5, intensity=100):
        """Generate a SYN flood attack"""
        print(f"\n[*] Starting SYN flood against {self.target_ip}")
        start_time = time.time()
        packets_sent = 0
        
        with tqdm(total=duration*intensity, desc="SYN flood") as pbar:
            while time.time() - start_time < duration:
                for _ in range(intensity):
                    packet = IP(src=self.source_ip, dst=self.target_ip)/TCP(
                        sport=random.randint(1024, 65535),
                        dport=80,
                        flags="S"
                    )
                    send(packet, verbose=False, iface=self.interface)
                    packets_sent += 1
                    pbar.update(1)
                time.sleep(0.001)
        
        print(f"Sent {packets_sent} SYN flood packets")

def main():
    parser = argparse.ArgumentParser(description='Generate suspicious traffic patterns')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--interface', default='eth0', help='Network interface to use')
    parser.add_argument('--attack', choices=['portscan', 'ddos', 'pingflood', 'synflood', 'all'],
                      default='all', help='Type of attack to generate')
    parser.add_argument('--intensity', type=int, default=100,
                      help='Attack intensity (packets per second)')
    args = parser.parse_args()

    try:
        generator = SuspiciousTrafficGenerator(args.target, interface=args.interface)
        
        attacks = {
            'portscan': lambda: generator.generate_port_scan(num_ports=1000),
            'ddos': lambda: generator.generate_ddos(duration=5, intensity=args.intensity),
            'pingflood': lambda: generator.generate_ping_flood(count=500),
            'synflood': lambda: generator.generate_syn_flood(duration=5, intensity=args.intensity)
        }

        if args.attack == 'all':
            for attack_func in attacks.values():
                attack_func()
        else:
            attacks[args.attack]()

    except KeyboardInterrupt:
        print("\n[!] Attack simulation interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main() 