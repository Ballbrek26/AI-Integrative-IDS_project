from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['packet_rate'] > 50 and  # More than 50 packets per second
                    features['packet_size'] < 100  # Small packets typical of SYN flood
                ),
                'description': 'Potential SYN flood attack detected'
            },
            'ddos': {
                'condition': lambda features: (
                    features['packet_rate'] > 100 and  # High packet rate
                    features['byte_rate'] > 50000  # High byte rate
                ),
                'description': 'Potential DDoS attack detected'
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and  # Small packets
                    features['packet_rate'] > 20  # Moderate packet rate
                ),
                'description': 'Potential port scanning activity detected'
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        """Train the anomaly detector with normal traffic data"""
        print("[*] Training anomaly detector with", len(normal_traffic_data), "samples")
        self.anomaly_detector.fit(normal_traffic_data)
        self.is_trained = True
        print("[+] Anomaly detector training completed")

    def detect_threats(self, features):
        threats = []

        # Ensure we have all required features
        required_features = {'packet_size', 'packet_rate', 'byte_rate'}
        if not all(feature in features for feature in required_features):
            print(f"[!] Missing required features. Available features: {list(features.keys())}")
            return threats

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'name': rule_name,
                        'description': rule['description'],
                        'confidence': 0.9,
                        'features': {k: features[k] for k in required_features}
                    })
            except Exception as e:
                print(f"[!] Error checking rule {rule_name}: {str(e)}")

        # Anomaly-based detection (only if trained)
        if self.is_trained:
            try:
                feature_vector = np.array([[
                    features['packet_size'],
                    features['packet_rate'],
                    features['byte_rate']
                ]])

                anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                if anomaly_score < -0.5:  # Threshold for anomaly detection
                    threats.append({
                        'type': 'anomaly',
                        'name': 'unusual_traffic',
                        'description': 'Anomalous traffic pattern detected',
                        'score': float(anomaly_score),
                        'confidence': min(1.0, abs(float(anomaly_score))),
                        'features': {k: features[k] for k in required_features}
                    })
            except Exception as e:
                print(f"[!] Error in anomaly detection: {str(e)}")

        return threats