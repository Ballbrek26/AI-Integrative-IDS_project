from .Packet_Capture import PacketCapture
from .Traffic_Analyzer import TrafficAnalyzer
from .Detection_Engine import DetectionEngine
from .Alert_System import AlertSystem
from scapy.all import IP, TCP
import queue

class IntrusionDetectionSystem:
    def __init__(self, interface="eth0", train_data_path=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

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

    def start(self):
        """
        Start the AI-Integrative-IDS to monitor network traffic.
        """
        print(f"Starting AI-Integrative-IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping AI-Integrative-IDS...")
                self.packet_capture.stop()
                break

# Export the classes for easier access
__all__ = [
    'PacketCapture',
    'TrafficAnalyzer',
    'DetectionEngine',
    'AlertSystem',
    'IntrusionDetectionSystem'
]