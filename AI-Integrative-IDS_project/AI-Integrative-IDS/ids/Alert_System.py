import logging
import json
from datetime import datetime
import sys
from termcolor import colored
import time
import os

class AlertSystem:
    def __init__(self, log_dir="logs"):
        # Create logs directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Initialize log files with timestamps
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.alert_log = os.path.join(log_dir, f'alerts_{timestamp}.log')
        self.packet_log = os.path.join(log_dir, f'packets_{timestamp}.log')
        self.stats_log = os.path.join(log_dir, f'stats_{timestamp}.log')

        # Set up alert logging
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # Alert file handler
        alert_handler = logging.FileHandler(self.alert_log)
        alert_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        alert_handler.setFormatter(alert_formatter)
        self.logger.addHandler(alert_handler)

        # Packet logging
        self.packet_logger = logging.getLogger("IDS_Packets")
        self.packet_logger.setLevel(logging.INFO)
        packet_handler = logging.FileHandler(self.packet_log)
        packet_formatter = logging.Formatter('%(asctime)s - %(message)s')
        packet_handler.setFormatter(packet_formatter)
        self.packet_logger.addHandler(packet_handler)

        # Stats logging
        self.stats_logger = logging.getLogger("IDS_Stats")
        self.stats_logger.setLevel(logging.INFO)
        stats_handler = logging.FileHandler(self.stats_log)
        stats_formatter = logging.Formatter('%(asctime)s - %(message)s')
        stats_handler.setFormatter(stats_formatter)
        self.stats_logger.addHandler(stats_handler)

        # Console handler with no formatting (we'll handle it ourselves)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(console_handler)

        # Print startup banner
        self.print_banner()
        print(colored(f"[*] Alert system initialized. Logging to directory: {log_dir}", 'cyan'))
        print(colored(f"[*] Alert log: {self.alert_log}", 'cyan'))
        print(colored(f"[*] Packet log: {self.packet_log}", 'cyan'))
        print(colored(f"[*] Stats log: {self.stats_log}", 'cyan'))
        print(colored("=" * 80, 'cyan'))

    def print_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                     AI-Integrative Intrusion Detection System                 ║
║                        Real-time Network Traffic Monitor                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(colored(banner, 'cyan', attrs=['bold']))

    def get_threat_color(self, threat_type, confidence):
        """Determine color based on threat type and confidence"""
        if confidence > 0.8:
            return 'red'
        elif confidence > 0.5:
            return 'yellow'
        return 'white'

    def format_packet_info(self, packet_info):
        """Format packet information with colors"""
        return (
            f"│ Source: {colored(f"{packet_info['source_ip']}:{packet_info['source_port']}", 'green')}\n"
            f"│ Destination: {colored(f"{packet_info['destination_ip']}:{packet_info['destination_port']}", 'blue')}"
        )

    def format_features(self, features):
        """Format feature information with colors"""
        return (
            f"│ Packet Size: {colored(f"{features.get('packet_size', 'N/A'):>6.0f} bytes", 'cyan')}\n"
            f"│ Packet Rate: {colored(f"{features.get('packet_rate', 'N/A'):>6.1f} pps", 'cyan')}\n"
            f"│ Byte Rate: {colored(f"{features.get('byte_rate', 'N/A')/1000:>6.1f} KB/s", 'cyan')}"
        )

    def log_packet(self, packet_info, features):
        """Log packet information to packet log"""
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet_info.get('source_ip', 'unknown'),
            'destination_ip': packet_info.get('destination_ip', 'unknown'),
            'source_port': packet_info.get('source_port', 'unknown'),
            'destination_port': packet_info.get('destination_port', 'unknown'),
            'packet_size': features.get('packet_size', 'N/A'),
            'packet_rate': features.get('packet_rate', 'N/A'),
            'byte_rate': features.get('byte_rate', 'N/A')
        }
        self.packet_logger.info(json.dumps(packet_data))

    def generate_alert(self, threat, packet_info):
        # Create alert details for logging
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'threat_name': threat.get('name', 'unknown'),
            'description': threat.get('description', 'Unknown threat detected'),
            'source_ip': packet_info.get('source_ip', 'unknown'),
            'destination_ip': packet_info.get('destination_ip', 'unknown'),
            'source_port': packet_info.get('source_port', 'unknown'),
            'destination_port': packet_info.get('destination_port', 'unknown'),
            'confidence': threat.get('confidence', 0.0),
            'features': threat.get('features', {})
        }

        # Get alert color based on confidence
        alert_color = self.get_threat_color(threat['type'], threat['confidence'])

        # Format timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Build the visual alert
        visual_alert = [
            "╔" + "═" * 78 + "╗",
            f"║ {colored('ALERT DETECTED', alert_color, attrs=['bold']):^78} ║",
            "╠" + "═" * 78 + "╣",
            f"║ {colored(timestamp, 'white'):^78} ║",
            "╟" + "─" * 78 + "╢",
            f"║ Type: {colored(threat['type'].upper(), alert_color, attrs=['bold'])} - {threat['description']: <54} ║",
            "╟" + "─" * 78 + "╢",
            f"║ {self.format_packet_info(packet_info)} {' ' * 35}║",
            "╟" + "─" * 78 + "╢",
            f"║ {self.format_features(threat['features'])} {' ' * 35}║",
            "╟" + "─" * 78 + "╢",
            f"║ Confidence: {colored(f'{threat['confidence']:.2%}', alert_color, attrs=['bold']): <69} ║",
            "╚" + "═" * 78 + "╝"
        ]

        # Print the visual alert
        print("\n".join(visual_alert))

        # Log the full alert to file
        if threat['confidence'] > 0.8:
            self.logger.critical(json.dumps(alert))
        else:
            self.logger.warning(json.dumps(alert))

        # Log packet information
        self.log_packet(packet_info, threat['features'])

    def log_traffic_stats(self, stats):
        """Log traffic statistics with visualization"""
        stats_display = [
            "╔══════════════════════ Traffic Statistics ══════════════════════╗",
            f"║ Total Packets: {stats['total_packets']:>8} │ Alerts Generated: {stats['total_alerts']:>8} ║",
            f"║ Packet Rate:   {stats['packet_rate']:>8.1f} │ Alert Rate:      {stats['alert_rate']:>8.1f} ║",
            "╚═════════════════════════════════════════════════════════════════╝"
        ]
        print(colored("\n".join(stats_display), 'cyan'))
        
        # Log stats to file
        self.stats_logger.info(json.dumps(stats))