import pandas as pd
import numpy as np

def generate_normal_traffic_data(num_samples=1000):
    """
    Generate synthetic normal traffic data for training.
    """
    np.random.seed(42)
    
    # Generate realistic packet sizes (mostly small packets with some larger ones)
    packet_sizes = np.random.lognormal(mean=5, sigma=1, size=num_samples)
    
    # Generate realistic packet rates (mostly low rates with some spikes)
    packet_rates = np.random.lognormal(mean=2, sigma=0.5, size=num_samples)
    
    # Calculate byte rates based on packet sizes and rates
    byte_rates = packet_sizes * packet_rates
    
    # Create DataFrame
    df = pd.DataFrame({
        'packet_size': packet_sizes,
        'packet_rate': packet_rates,
        'byte_rate': byte_rates
    })
    
    # Save to CSV
    df.to_csv('normal_traffic.csv', index=False)
    print(f"Generated {num_samples} samples of normal traffic data in 'normal_traffic.csv'")

if __name__ == "__main__":
    generate_normal_traffic_data()
