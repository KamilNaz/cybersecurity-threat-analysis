"""
Cybersecurity Threat Detection System
Author: Kamil Nazaruk
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime


class ThreatAnalyzer:
    """
    Advanced threat analysis system for cybersecurity log data.

    Attributes:
        data (pd.DataFrame): Processed security log data
        model (IsolationForest): Anomaly detection model
        scaler (StandardScaler): Feature scaling transformer
    """

    def __init__(self, contamination=0.1):
        """
        Initialize ThreatAnalyzer with anomaly detection model.

        Args:
            contamination (float): Expected proportion of anomalies (default: 0.1)
        """
        self.data = None
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.threat_scores = None

    def load_logs(self, filepath):
        """
        Load and preprocess security logs from CSV file.

        Args:
            filepath (str): Path to security log CSV file

        Returns:
            pd.DataFrame: Loaded log data
        """
        print(f"[*] Loading logs from {filepath}...")
        self.data = pd.read_csv(filepath)
        print(f"[+] Loaded {len(self.data)} log entries")
        return self.data

    def preprocess_data(self):
        """
        Clean and preprocess log data for analysis.

        Returns:
            pd.DataFrame: Preprocessed data
        """
        print("[*] Preprocessing data...")

        # Convert timestamp to datetime
        if 'timestamp' in self.data.columns:
            self.data['timestamp'] = pd.to_datetime(self.data['timestamp'])
            self.data['hour'] = self.data['timestamp'].dt.hour
            self.data['day_of_week'] = self.data['timestamp'].dt.dayofweek

        # Handle missing values
        self.data = self.data.fillna(0)

        # Extract numeric features
        numeric_columns = self.data.select_dtypes(include=[np.number]).columns
        self.data['log_index'] = range(len(self.data))

        print(f"[+] Preprocessing complete. Features: {list(numeric_columns)}")
        return self.data

    def detect_threats(self, features=None):
        """
        Detect potential threats using anomaly detection.

        Args:
            features (list): List of feature columns to use (optional)

        Returns:
            pd.DataFrame: Data with threat predictions and scores
        """
        print("[*] Running threat detection...")

        if features is None:
            # Use all numeric features
            features = self.data.select_dtypes(include=[np.number]).columns.tolist()
            features = [f for f in features if f != 'threat_label']

        X = self.data[features]

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Detect anomalies
        predictions = self.model.fit_predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)

        # Add results to dataframe
        self.data['is_threat'] = predictions == -1
        self.data['threat_score'] = -anomaly_scores  # Higher = more anomalous
        self.threat_scores = anomaly_scores

        threat_count = self.data['is_threat'].sum()
        print(f"[!] Detected {threat_count} potential threats ({threat_count/len(self.data)*100:.2f}%)")

        return self.data[self.data['is_threat']]

    def classify_threats(self):
        """
        Classify detected threats by severity level.

        Returns:
            pd.DataFrame: Threat classification summary
        """
        if 'threat_score' not in self.data.columns:
            raise ValueError("Run detect_threats() first")

        # Define severity levels based on threat score
        self.data['severity'] = pd.cut(
            self.data['threat_score'],
            bins=[0, 0.3, 0.6, 1.0],
            labels=['Low', 'Medium', 'High']
        )

        severity_counts = self.data['severity'].value_counts()
        print("\n[*] Threat Severity Distribution:")
        print(severity_counts)

        return severity_counts

    def plot_threat_landscape(self, figsize=(15, 10)):
        """
        Create comprehensive visualization of threat landscape.

        Args:
            figsize (tuple): Figure size (width, height)
        """
        if self.data is None:
            raise ValueError("No data loaded")

        fig, axes = plt.subplots(2, 2, figsize=figsize)
        fig.suptitle('Cybersecurity Threat Analysis Dashboard', fontsize=16, fontweight='bold')

        # 1. Threat Score Distribution
        ax1 = axes[0, 0]
        ax1.hist(self.data['threat_score'], bins=50, color='#e74c3c', alpha=0.7, edgecolor='black')
        ax1.axvline(self.data['threat_score'].mean(), color='blue', linestyle='--',
                    label=f'Mean: {self.data["threat_score"].mean():.3f}')
        ax1.set_xlabel('Threat Score')
        ax1.set_ylabel('Frequency')
        ax1.set_title('Threat Score Distribution')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # 2. Threats vs Normal Traffic
        ax2 = axes[0, 1]
        threat_counts = self.data['is_threat'].value_counts()
        colors = ['#2ecc71', '#e74c3c']
        ax2.pie(threat_counts, labels=['Normal', 'Threat'], autopct='%1.1f%%',
                colors=colors, startangle=90, explode=(0, 0.1))
        ax2.set_title('Threat Detection Results')

        # 3. Hourly Threat Activity
        if 'hour' in self.data.columns:
            ax3 = axes[1, 0]
            hourly_threats = self.data.groupby('hour')['is_threat'].sum()
            ax3.bar(hourly_threats.index, hourly_threats.values, color='#3498db', alpha=0.7)
            ax3.set_xlabel('Hour of Day')
            ax3.set_ylabel('Number of Threats')
            ax3.set_title('Threat Activity by Hour')
            ax3.grid(True, alpha=0.3, axis='y')

        # 4. Severity Heatmap
        if 'severity' in self.data.columns:
            ax4 = axes[1, 1]
            severity_counts = self.data['severity'].value_counts()
            ax4.barh(severity_counts.index, severity_counts.values,
                    color=['#f39c12', '#e67e22', '#c0392b'])
            ax4.set_xlabel('Count')
            ax4.set_title('Threat Severity Levels')
            ax4.grid(True, alpha=0.3, axis='x')

        plt.tight_layout()
        plt.savefig('threat_analysis_dashboard.png', dpi=300, bbox_inches='tight')
        print("\n[+] Visualization saved as 'threat_analysis_dashboard.png'")
        plt.show()

    def generate_report(self):
        """
        Generate comprehensive threat analysis report.

        Returns:
            dict: Report statistics
        """
        report = {
            'total_events': len(self.data),
            'threats_detected': self.data['is_threat'].sum(),
            'threat_percentage': (self.data['is_threat'].sum() / len(self.data)) * 100,
            'avg_threat_score': self.data['threat_score'].mean(),
            'max_threat_score': self.data['threat_score'].max(),
        }

        if 'severity' in self.data.columns:
            report['severity_breakdown'] = self.data['severity'].value_counts().to_dict()

        print("\n" + "="*50)
        print("THREAT ANALYSIS REPORT")
        print("="*50)
        print(f"Total Events Analyzed: {report['total_events']:,}")
        print(f"Threats Detected: {report['threats_detected']:,} ({report['threat_percentage']:.2f}%)")
        print(f"Average Threat Score: {report['avg_threat_score']:.4f}")
        print(f"Maximum Threat Score: {report['max_threat_score']:.4f}")

        if 'severity_breakdown' in report:
            print("\nSeverity Breakdown:")
            for severity, count in report['severity_breakdown'].items():
                print(f"  {severity}: {count:,}")

        print("="*50 + "\n")

        return report


# Example usage
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = ThreatAnalyzer(contamination=0.1)

    # Generate sample data for demonstration
    print("[*] Generating sample security log data...")
    np.random.seed(42)
    n_samples = 10000

    sample_data = pd.DataFrame({
        'timestamp': pd.date_range('2024-01-01', periods=n_samples, freq='1min'),
        'src_ip': np.random.choice(['192.168.1.' + str(i) for i in range(1, 50)], n_samples),
        'dst_port': np.random.choice([80, 443, 22, 3389, 8080], n_samples),
        'packet_count': np.random.poisson(100, n_samples),
        'byte_count': np.random.exponential(5000, n_samples),
        'duration': np.random.exponential(30, n_samples),
    })

    # Add some anomalies
    anomaly_indices = np.random.choice(n_samples, size=int(n_samples*0.1), replace=False)
    sample_data.loc[anomaly_indices, 'packet_count'] *= 10
    sample_data.loc[anomaly_indices, 'byte_count'] *= 20

    sample_data.to_csv('/home/user/cybersecurity-threat-analysis/data/raw/security_logs.csv', index=False)

    # Run analysis
    analyzer.load_logs('/home/user/cybersecurity-threat-analysis/data/raw/security_logs.csv')
    analyzer.preprocess_data()
    threats = analyzer.detect_threats()
    analyzer.classify_threats()
    analyzer.plot_threat_landscape()
    report = analyzer.generate_report()
