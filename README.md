# AI-Integrative IDS (Intrusion Detection System)

## Project Overview
AI-Integrative IDS is a hybrid network security monitoring system that combines traditional signature-based detection with AI-powered anomaly detection. The system provides real-time network traffic analysis and alert generation for various types of cyber threats.

### Key Features
- Dual detection approach (signature-based and anomaly-based)
- Real-time packet capture and analysis
- Automated alert generation
- Traffic statistics monitoring
- Configurable network interface monitoring
- Detailed logging system

### Detection Capabilities
- SYN Flood attacks
- DDoS attempts
- Port scanning activities
- Anomalous traffic patterns
- Unusual packet rates and sizes

## Use Cases
This IDS can be deployed in various environments:
1. **Corporate Networks**: Monitor internal network traffic for potential threats
2. **Small Business Networks**: Protect against common network attacks
3. **Educational Institutions**: Network security monitoring and research
4. **Security Testing**: Test network security measures and responses
5. **Security Research**: Analyze different attack patterns and behaviors

## Installation

### Prerequisites
- Python 3.x
- Root/Administrator privileges
- Linux-based operating system (tested on Kali Linux)

### Dependencies
```bash
pandas>=1.5.3
numpy>=1.24.2
scapy>=2.5.0
tqdm>=4.65.0
```

### Setup Instructions
1. Clone the repository:
```bash
git clone https://github.com/Ballbrek26/AI-Integrative-IDS_project.git
cd AI-Integrative-IDS
```

2. Create and activate virtual environment:
```bash
python3 -m venv ids_env
source ids_env/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage Guide

### 1. Generate Normal Traffic Data
Generate baseline normal traffic data for training:
```bash
sudo python3 -m ids.generate_normal_traffic
```
This command will:
- Generate 1000 normal traffic packets
- Save the data to normal_traffic.csv
- Train the IDS with the generated data

### 2. Run the IDS
Start monitoring network traffic:
```bash
sudo python3 -m ids.run_ids --interface lo --model normal_traffic.csv
```
Parameters:
- `--interface`: Network interface to monitor (default: lo)
- `--model`: Path to training data file (default: normal_traffic.csv)

### 3. Generate Test Traffic (Optional)
For testing the IDS, you can generate suspicious traffic patterns:
```bash
sudo python3 -m ids.generate_suspicious_traffic --target [target-ip] --interface lo --attack all
```
Attack options:
- `all`: Run all attack types
- `portscan`: Port scanning simulation
- `ddos`: DDoS attack simulation
- `pingflood`: ICMP flood
- `synflood`: TCP SYN flood

## Project Structure
