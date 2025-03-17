from .IDS_main import IntrusionDetectionSystem
from .Packet_Capture import PacketCapture
from .Traffic_Analyzer import TrafficAnalyzer
from .Detection_Engine import DetectionEngine
from .Alert_System import AlertSystem

__version__ = '1.0.0'

__all__ = [
    'IntrusionDetectionSystem',
    'PacketCapture',
    'TrafficAnalyzer',
    'DetectionEngine',
    'AlertSystem'
]

if __name__ == "__main__":
    # Path to the training data
    train_data_path = "normal_traffic.csv"  # Set to None if you don't want to train

    # Initialize and start the AI-Integrative-IDS
    ids = IntrusionDetectionSystem(interface="Wi-Fi", train_data_path=train_data_path)
    ids.start()