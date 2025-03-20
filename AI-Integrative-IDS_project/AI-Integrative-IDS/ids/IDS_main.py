from .Packet_Capture import PacketCapture
from .Traffic_Analyzer import TrafficAnalyzer
from .Detection_Engine import DetectionEngine
from .Alert_System import AlertSystem
from scapy.all import IP, TCP, UDP, ICMP
import queue
import time

class IntrusionDetectionSystem:
    def __init__(self, interface="eth0", train_data_path=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface
        
        # Statistics
        self.stats = {
            'start_time': time.time(),
            'total_packets': 0,
            'total_alerts': 0,
            'last_stats_time': time.time()
        }

        # Train the model if training data is provided
        if train_data_path:
            self.train_model(train_data_path)

    def train_model(self, train_data_path):
        """
        Train the DetectionEngine using the provided training data.
        """
        import pandas as pd

        # Load the training data
        print("Loading training data...")
        normal_traffic_data = pd.read_csv(train_data_path)
        normal_traffic_data = normal_traffic_data[['packet_size', 'packet_rate', 'byte_rate']].values

        # Train the model
        print("Training the model...")
        self.detection_engine.train_anomaly_detector(normal_traffic_data)
        print("Model trained successfully.")

    def get_packet_info(self, packet):
        """Extract packet information safely"""
        info = {'source_ip': 'unknown', 'destination_ip': 'unknown',
                'source_port': 'unknown', 'destination_port': 'unknown'}
        
        if IP in packet:
            info['source_ip'] = packet[IP].src
            info['destination_ip'] = packet[IP].dst
            
            if TCP in packet:
                info['source_port'] = packet[TCP].sport
                info['destination_port'] = packet[TCP].dport
            elif UDP in packet:
                info['source_port'] = packet[UDP].sport
                info['destination_port'] = packet[UDP].dport
            elif ICMP in packet:
                info['source_port'] = 'ICMP'
                info['destination_port'] = 'ICMP'
        
        return info

    def update_stats(self, alerts=0):
        """Update traffic statistics"""
        current_time = time.time()
        self.stats['total_packets'] += 1
        self.stats['total_alerts'] += alerts
        
        # Update rates every second
        if current_time - self.stats['last_stats_time'] >= 1:
            elapsed_time = current_time - self.stats['start_time']
            stats = {
                'total_packets': self.stats['total_packets'],
                'total_alerts': self.stats['total_alerts'],
                'packet_rate': self.stats['total_packets'] / elapsed_time,
                'alert_rate': self.stats['total_alerts'] / elapsed_time
            }
            self.alert_system.log_traffic_stats(stats)
            self.stats['last_stats_time'] = current_time

    def start(self):
        """
        Start the AI-Integrative-IDS to monitor network traffic.
        Processes one packet per second for better readability.
        """
        print(f"Starting AI-Integrative-IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)
        self.stats['start_time'] = time.time()
        self.stats['last_stats_time'] = time.time()
        last_packet_time = time.time()

        while True:
            try:
                current_time = time.time()
                # Wait until a second has passed since the last packet
                if current_time - last_packet_time < 1.0:
                    time.sleep(0.1)  # Sleep for 100ms to prevent CPU overuse
                    continue

                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                packet_info = self.get_packet_info(packet)

                if features:
                    # Log every packet that has features extracted
                    self.alert_system.log_packet(packet_info, features)
                    
                    threats = self.detection_engine.detect_threats(features)
                    if threats:
                        for threat in threats:
                            self.alert_system.generate_alert(threat, packet_info)
                    self.update_stats(len(threats))
                else:
                    self.update_stats()

                # Update the last packet time
                last_packet_time = current_time

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("\nStopping AI-Integrative-IDS...")
                self.packet_capture.stop()
                break
            except Exception as e:
                print(f"\n[!] Error processing packet: {str(e)}")
                continue

# Export the classes for easier access
__all__ = [
    'PacketCapture',
    'TrafficAnalyzer',
    'DetectionEngine',
    'AlertSystem',
    'IntrusionDetectionSystem'
]