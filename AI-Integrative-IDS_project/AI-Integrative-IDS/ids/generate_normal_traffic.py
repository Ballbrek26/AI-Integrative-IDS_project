#!/usr/bin/env python3
import os
import sys
import time
import random
import csv
from datetime import datetime

def check_dependencies():
    """Check if all required packages are installed"""
    required_packages = {
        'pandas': 'python3-pandas',
        'numpy': 'python3-numpy',
        'scapy': 'python3-scapy',
        'tqdm': 'python3-tqdm'
    }
    
    missing_packages = []
    
    for package, apt_name in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(apt_name)
    
    if missing_packages:
        print("Missing required packages. Please install them using:")
        print(f"sudo apt install {' '.join(missing_packages)}")
        sys.exit(1)

def check_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0

def generate_normal_traffic(num_packets=10000, output_file="normal_traffic.csv"):
    """
    Generate normal traffic patterns and save them to a CSV file
    num_packets: Number of packets to generate
    """
    if not check_root():
        raise PermissionError(
            "This script requires root privileges to send network packets.\n"
            "Please run it with sudo: sudo python3 -m ids.generate_normal_traffic"
        )

    # Import packages after checking dependencies
    import pandas as pd
    import numpy as np
    from scapy.all import IP, TCP, send, RandIP
    from tqdm import tqdm

    print(f"Generating {num_packets} normal traffic packets...")
    
    # Initialize lists to store traffic data
    data = []
    packets_sent = 0
    
    try:
        with tqdm(total=num_packets, desc="Generating packets") as pbar:
            while packets_sent < num_packets:
                # Generate normal traffic patterns
                packet_size = np.random.normal(500, 100)  # Normal distribution around 500 bytes
                packet_rate = np.random.normal(100, 20)   # Normal distribution around 100 packets/sec
                byte_rate = packet_size * packet_rate
                
                # Create and send a benign packet
                src_port = random.randint(1024, 65535)  # Random source port
                packet = IP(src=RandIP(), dst=RandIP())/TCP(sport=src_port, dport=80)
                send(packet, verbose=False)
                
                # Store the traffic features
                data.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'packet_size': packet_size,
                    'packet_rate': packet_rate,
                    'byte_rate': byte_rate
                })
                
                packets_sent += 1
                pbar.update(1)
                
                # Add small delay to prevent overwhelming the network
                time.sleep(0.01)  # 10ms delay between packets
                
    except KeyboardInterrupt:
        print(f"\nTraffic generation interrupted by user after {packets_sent} packets.")
    except Exception as e:
        print(f"\nError during traffic generation: {str(e)}")
        raise
    
    # Save to CSV
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"\nNormal traffic data saved to {output_file}")
    print(f"Generated {packets_sent} packets")
    return output_file

if __name__ == "__main__":
    try:
        # Check dependencies first
        check_dependencies()
        
        # Generate normal traffic
        training_data = generate_normal_traffic(num_packets=10000)
        
        # Import IDS after dependency check
        from ids.IDS_main import IntrusionDetectionSystem
        
        # Initialize and train IDS
        ids = IntrusionDetectionSystem(interface="eth0", train_data_path=training_data)
        print("IDS trained successfully with normal traffic patterns.")
    except PermissionError as e:
        print(f"\nError: {str(e)}")
        exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        exit(1) 