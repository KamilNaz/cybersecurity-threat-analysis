"""
Utility functions for threat analysis
"""

import pandas as pd
import numpy as np
from pathlib import Path


def generate_sample_data(n_samples=10000, anomaly_ratio=0.1, output_path=None):
    """
    Generate synthetic security log data for demonstration.

    Args:
        n_samples (int): Number of log entries to generate
        anomaly_ratio (float): Proportion of anomalous events (0-1)
        output_path (str): Path to save CSV file (optional)

    Returns:
        pd.DataFrame: Generated security log data
    """
    print(f"[*] Generating {n_samples:,} sample security log entries...")
    np.random.seed(42)

    # Generate normal network traffic patterns
    data = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=n_samples, freq='1min'),
        'src_ip': np.random.choice([f'192.168.1.{i}' for i in range(1, 50)], n_samples),
        'dst_port': np.random.choice([80, 443, 22, 3389, 8080], n_samples),
        'packet_count': np.random.poisson(100, n_samples),
        'byte_count': np.random.exponential(5000, n_samples),
        'duration': np.random.exponential(30, n_samples),
    })

    # Inject anomalies (simulated attacks)
    n_anomalies = int(n_samples * anomaly_ratio)
    anomaly_indices = np.random.choice(n_samples, size=n_anomalies, replace=False)

    # Anomalies have unusual traffic patterns
    data.loc[anomaly_indices, 'packet_count'] *= np.random.uniform(5, 20, n_anomalies)
    data.loc[anomaly_indices, 'byte_count'] *= np.random.uniform(10, 50, n_anomalies)
    data.loc[anomaly_indices, 'duration'] *= np.random.uniform(2, 10, n_anomalies)

    # Mark actual anomalies for validation (not used in detection)
    data['true_label'] = 0
    data.loc[anomaly_indices, 'true_label'] = 1

    print(f"[+] Generated {n_samples:,} events ({n_anomalies:,} anomalies)")

    # Save if path provided
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        data.to_csv(output_path, index=False)
        print(f"[+] Saved to {output_path}")

    return data
