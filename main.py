#!/usr/bin/env python3
"""
Cybersecurity Threat Analysis - Main Entry Point
Author: Kamil Nazaruk

Usage:
    python main.py --demo                    # Run with generated sample data
    python main.py --file logs.csv           # Analyze your own log file
    python main.py --demo --no-viz           # Run demo without visualization
"""

import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.threat_detector import ThreatAnalyzer
from src.utils import generate_sample_data


def run_demo(visualize=True):
    """Run demonstration with generated sample data."""
    print("\n" + "="*60)
    print("CYBERSECURITY THREAT ANALYSIS - DEMO MODE")
    print("="*60 + "\n")

    # Generate sample data
    data_path = "data/raw/sample_security_logs.csv"
    data = generate_sample_data(n_samples=10000, anomaly_ratio=0.1, output_path=data_path)

    # Initialize and run analysis
    analyzer = ThreatAnalyzer(contamination=0.1)
    analyzer.load_logs(data_path)
    analyzer.preprocess_data()

    print("\n[*] Running threat detection...")
    threats = analyzer.detect_threats()

    print("\n[*] Classifying threat severity...")
    analyzer.classify_threats()

    if visualize:
        print("\n[*] Generating visualizations...")
        analyzer.plot_threat_landscape()

    print("\n[*] Generating final report...")
    report = analyzer.generate_report()

    # Calculate accuracy (using true_label from sample data)
    if 'true_label' in analyzer.data.columns:
        true_positives = ((analyzer.data['is_threat'] == True) & (analyzer.data['true_label'] == 1)).sum()
        false_positives = ((analyzer.data['is_threat'] == True) & (analyzer.data['true_label'] == 0)).sum()
        true_negatives = ((analyzer.data['is_threat'] == False) & (analyzer.data['true_label'] == 0)).sum()
        false_negatives = ((analyzer.data['is_threat'] == False) & (analyzer.data['true_label'] == 1)).sum()

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        print("\n" + "="*60)
        print("MODEL PERFORMANCE METRICS")
        print("="*60)
        print(f"Precision: {precision:.2%}")
        print(f"Recall:    {recall:.2%}")
        print(f"F1-Score:  {f1_score:.2%}")
        print(f"True Positives:  {true_positives:,}")
        print(f"False Positives: {false_positives:,}")
        print(f"True Negatives:  {true_negatives:,}")
        print(f"False Negatives: {false_negatives:,}")
        print("="*60 + "\n")

    print("[+] Demo complete! Check 'threat_analysis_dashboard.png' for visualizations.\n")


def run_analysis(filepath, visualize=True):
    """Run analysis on user-provided log file."""
    print("\n" + "="*60)
    print("CYBERSECURITY THREAT ANALYSIS")
    print("="*60 + "\n")

    if not Path(filepath).exists():
        print(f"[!] Error: File '{filepath}' not found!")
        sys.exit(1)

    # Initialize and run analysis
    analyzer = ThreatAnalyzer(contamination=0.1)
    analyzer.load_logs(filepath)
    analyzer.preprocess_data()

    print("\n[*] Running threat detection...")
    threats = analyzer.detect_threats()

    print("\n[*] Classifying threat severity...")
    analyzer.classify_threats()

    if visualize:
        print("\n[*] Generating visualizations...")
        analyzer.plot_threat_landscape()

    print("\n[*] Generating final report...")
    report = analyzer.generate_report()

    # Save detected threats
    output_path = "data/processed/detected_threats.csv"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    threats.to_csv(output_path, index=False)
    print(f"\n[+] Detected threats saved to: {output_path}")

    print("[+] Analysis complete!\n")


def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Threat Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo              # Run with sample data
  python main.py --file logs.csv     # Analyze your own data
  python main.py --demo --no-viz     # Run without visualization
        """
    )

    parser.add_argument('--demo', action='store_true',
                        help='Run demonstration with generated sample data')
    parser.add_argument('--file', type=str,
                        help='Path to security log CSV file')
    parser.add_argument('--no-viz', action='store_true',
                        help='Skip visualization generation')

    args = parser.parse_args()

    # Ensure data directories exist
    Path("data/raw").mkdir(parents=True, exist_ok=True)
    Path("data/processed").mkdir(parents=True, exist_ok=True)

    if args.demo:
        run_demo(visualize=not args.no_viz)
    elif args.file:
        run_analysis(args.file, visualize=not args.no_viz)
    else:
        parser.print_help()
        print("\n[!] Error: Please specify --demo or --file <path>")
        sys.exit(1)


if __name__ == "__main__":
    main()
