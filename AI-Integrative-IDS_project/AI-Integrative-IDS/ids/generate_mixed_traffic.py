from scapy.all import IP, TCP, UDP, ICMP, Raw, send
import random
import time
import argparse
import ipaddress

class MixedTrafficGenerator:
    def __init__(self, target_ip, interface):
        self.target_ip = target_ip
        self.interface = interface
        self.source_ips = [
            str(ip) for ip in ipaddress.IPv4Network('192.168.0.0/24')
            if str(ip) != target_ip
        ]
        
        # Define normal traffic patterns
        self.normal_ports = [80, 443, 22, 53, 123]  # Common service ports
        self.normal_packet_sizes = range(64, 1024)  # Normal packet sizes
        
        # Define suspicious traffic patterns
        self.suspicious_ports = range(1, 65535)  # All ports for scanning
        self.suspicious_packet_sizes = range(1024, 8192)  # Larger packets for DDoS
        
    def generate_normal_packet(self):
        """Generate a normal-looking packet"""
        src_ip = random.choice(self.source_ips)
        dst_port = random.choice(self.normal_ports)
        src_port = random.randint(49152, 65535)  # Ephemeral ports
        size = random.choice(self.normal_packet_sizes)
        
        # Randomly choose between TCP and UDP for normal traffic
        if random.random() < 0.8:  # 80% TCP traffic
            packet = IP(src=src_ip, dst=self.target_ip) / \
                    TCP(sport=src_port, dport=dst_port) / \
                    Raw(RandString(size=size))
        else:  # 20% UDP traffic
            packet = IP(src=src_ip, dst=self.target_ip) / \
                    UDP(sport=src_port, dport=dst_port) / \
                    Raw(RandString(size=size))
        return packet
    
    def generate_suspicious_packet(self, attack_type="random"):
        """Generate a suspicious packet based on attack type"""
        src_ip = random.choice(self.source_ips)
        
        if attack_type == "random":
            attack_type = random.choice(["scan", "ddos", "synflood"])
            
        if attack_type == "scan":
            # Port scanning pattern
            dst_port = random.choice(list(self.suspicious_ports))
            packet = IP(src=src_ip, dst=self.target_ip) / \
                    TCP(sport=random.randint(49152, 65535), dport=dst_port, flags="S")
                    
        elif attack_type == "ddos":
            # DDoS pattern with large packets
            size = random.choice(self.suspicious_packet_sizes)
            packet = IP(src=src_ip, dst=self.target_ip) / \
                    UDP(sport=random.randint(49152, 65535), dport=53) / \
                    Raw(RandString(size=size))
                    
        else:  # synflood
            # SYN flood pattern
            packet = IP(src=src_ip, dst=self.target_ip) / \
                    TCP(sport=random.randint(49152, 65535), 
                        dport=random.choice([80, 443]), flags="S")
                    
        return packet

    def generate_mixed_traffic(self, duration=60, suspicious_ratio=0.3):
        """
        Generate mixed traffic for a specified duration
        suspicious_ratio: ratio of suspicious packets (0.0 to 1.0)
        """
        print(f"Generating mixed traffic for {duration} seconds...")
        print(f"Target IP: {self.target_ip}")
        print(f"Interface: {self.interface}")
        print(f"Suspicious packet ratio: {suspicious_ratio:.1%}")
        
        start_time = time.time()
        packet_count = 0
        
        try:
            while time.time() - start_time < duration:
                # Decide if this packet should be suspicious
                is_suspicious = random.random() < suspicious_ratio
                
                if is_suspicious:
                    packet = self.generate_suspicious_packet()
                    packet_type = "Suspicious"
                else:
                    packet = self.generate_normal_packet()
                    packet_type = "Normal"
                
                # Send the packet
                send(packet, iface=self.interface, verbose=False)
                packet_count += 1
                
                # Print progress
                print(f"\r[{packet_count}] Sent {packet_type} packet from {packet[IP].src} "
                      f"to {packet[IP].dst}:{packet[packet.lastlayer().name].dport}", 
                      end="", flush=True)
                
                # Random delay between packets (0.5 to 2 seconds)
                time.sleep(random.uniform(0.5, 2))
                
        except KeyboardInterrupt:
            print("\nStopping traffic generation...")
        
        print(f"\nSent {packet_count} packets in {time.time() - start_time:.1f} seconds")

def main():
    parser = argparse.ArgumentParser(description="Generate mixed network traffic")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--interface", required=True, help="Network interface to use")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--suspicious-ratio", type=float, default=0.3,
                      help="Ratio of suspicious packets (0.0 to 1.0)")
    
    args = parser.parse_args()
    
    generator = MixedTrafficGenerator(args.target, args.interface)
    generator.generate_mixed_traffic(args.duration, args.suspicious_ratio)

if __name__ == "__main__":
    main() 