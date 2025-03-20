from collections import defaultdict
from scapy.all import TCP, IP
import time

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)
            stats = self.flow_stats[flow_key]

            current_time = float(time.time())
            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)

            return self.extract_features(packet, stats)
        return None

    def extract_features(self, packet, stats):
        # Calculate time difference, ensure it's not zero
        time_diff = max(stats['last_time'] - stats['start_time'], 0.001)  # Use minimum of 1ms
        
        return {
            'packet_size': len(packet),
            'packet_rate': stats['packet_count'] / time_diff,
            'byte_rate': stats['byte_count'] / time_diff
        }