"""
Unit tests for ThreatAnalyzer
"""

import unittest
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threat_detector import ThreatAnalyzer
from src.utils import generate_sample_data


class TestThreatAnalyzer(unittest.TestCase):
    """Test cases for ThreatAnalyzer class"""

    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ThreatAnalyzer(contamination=0.1)
        self.sample_data = generate_sample_data(n_samples=1000, anomaly_ratio=0.1)

    def test_initialization(self):
        """Test ThreatAnalyzer initialization"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsNone(self.analyzer.data)
        self.assertIsNotNone(self.analyzer.model)
        self.assertIsNotNone(self.analyzer.scaler)

    def test_load_data_from_dataframe(self):
        """Test loading data from DataFrame"""
        # Save sample data to temp file
        temp_file = "/tmp/test_logs.csv"
        self.sample_data.to_csv(temp_file, index=False)

        # Load data
        data = self.analyzer.load_logs(temp_file)

        self.assertIsNotNone(data)
        self.assertEqual(len(data), 1000)
        self.assertIsInstance(data, pd.DataFrame)

    def test_preprocess_data(self):
        """Test data preprocessing"""
        temp_file = "/tmp/test_logs.csv"
        self.sample_data.to_csv(temp_file, index=False)

        self.analyzer.load_logs(temp_file)
        processed = self.analyzer.preprocess_data()

        self.assertIsNotNone(processed)
        self.assertIn('hour', processed.columns)
        self.assertIn('day_of_week', processed.columns)

    def test_detect_threats(self):
        """Test threat detection"""
        temp_file = "/tmp/test_logs.csv"
        self.sample_data.to_csv(temp_file, index=False)

        self.analyzer.load_logs(temp_file)
        self.analyzer.preprocess_data()
        threats = self.analyzer.detect_threats()

        self.assertIsNotNone(threats)
        self.assertIn('is_threat', self.analyzer.data.columns)
        self.assertIn('threat_score', self.analyzer.data.columns)
        self.assertGreater(len(threats), 0)  # Should detect some threats

    def test_classify_threats(self):
        """Test threat classification"""
        temp_file = "/tmp/test_logs.csv"
        self.sample_data.to_csv(temp_file, index=False)

        self.analyzer.load_logs(temp_file)
        self.analyzer.preprocess_data()
        self.analyzer.detect_threats()
        severity = self.analyzer.classify_threats()

        self.assertIsNotNone(severity)
        self.assertIn('severity', self.analyzer.data.columns)

    def test_generate_report(self):
        """Test report generation"""
        temp_file = "/tmp/test_logs.csv"
        self.sample_data.to_csv(temp_file, index=False)

        self.analyzer.load_logs(temp_file)
        self.analyzer.preprocess_data()
        self.analyzer.detect_threats()
        self.analyzer.classify_threats()
        report = self.analyzer.generate_report()

        self.assertIsNotNone(report)
        self.assertIn('total_events', report)
        self.assertIn('threats_detected', report)
        self.assertIn('threat_percentage', report)
        self.assertEqual(report['total_events'], 1000)

    def test_sample_data_generation(self):
        """Test sample data generator"""
        data = generate_sample_data(n_samples=500, anomaly_ratio=0.2)

        self.assertEqual(len(data), 500)
        self.assertIn('timestamp', data.columns)
        self.assertIn('src_ip', data.columns)
        self.assertIn('packet_count', data.columns)
        self.assertIn('true_label', data.columns)

        # Check anomaly ratio
        anomaly_count = data['true_label'].sum()
        expected_anomalies = 500 * 0.2
        self.assertAlmostEqual(anomaly_count, expected_anomalies, delta=10)


def run_tests():
    """Run all tests"""
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
