#!/usr/bin/env python3
import argparse
import signal
import sys
import os
from ids.IDS_main import IntrusionDetectionSystem

def signal_handler(sig, frame):
    print("\n[*] Shutting down IDS...")
    sys.exit(0)

def check_root():
    """Check if the script is running with root privileges"""
    if os.geteuid() != 0:
        raise PermissionError(
            "This script requires root privileges to capture packets.\n"
            "Please run it with sudo: sudo python3 -m ids.run_ids"
        )

def main():
    parser = argparse.ArgumentParser(description='Run the AI-Integrative IDS')
    parser.add_argument('--interface', default='eth0',
                      help='Network interface to monitor (default: eth0)')
    parser.add_argument('--model', default='normal_traffic.csv',
                      help='Path to trained model data')
    args = parser.parse_args()

    try:
        # Check for root privileges
        check_root()

        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)

        print(f"\n[*] Starting AI-Integrative IDS")
        print(f"[*] Monitoring interface: {args.interface}")
        print(f"[*] Using model: {args.model}")
        print("\n[*] Waiting for traffic...\n")

        # Initialize and start IDS
        ids = IntrusionDetectionSystem(
            interface=args.interface,
            train_data_path=args.model
        )
        
        # Start monitoring
        ids.start()

    except PermissionError as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"\n[!] Error: Model file '{args.model}' not found")
        print("[!] Please generate normal traffic first using:")
        print("    sudo python3 -m ids.generate_normal_traffic")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] IDS shutdown requested by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 