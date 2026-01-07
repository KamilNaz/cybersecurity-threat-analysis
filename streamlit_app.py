import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.threat_detector import ThreatAnalyzer
from src.utils import generate_sample_data

# Page config
st.set_page_config(
    page_title="Cybersecurity Threat Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #38bdf8;
        margin-bottom: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #38bdf8;
    }
    .stAlert {
        background-color: #1e293b;
        border-left-color: #38bdf8;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<p class="main-header">🛡️ Cybersecurity Threat Analysis Dashboard</p>', unsafe_allow_html=True)
st.markdown("**Real-time ML-based anomaly detection for security events**")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")

    data_source = st.radio(
        "Data Source:",
        ["Generate Sample Data", "Upload Custom Data"]
    )

    if data_source == "Generate Sample Data":
        n_samples = st.slider("Number of Events", 1000, 20000, 10000, 1000)
        anomaly_ratio = st.slider("Anomaly Ratio", 0.05, 0.20, 0.10, 0.01)
    else:
        uploaded_file = st.file_uploader("Upload CSV", type=['csv'])
        anomaly_ratio = st.slider("Expected Anomaly Ratio", 0.05, 0.20, 0.10, 0.01)

    st.divider()

    st.header("🎯 Detection Settings")
    contamination = st.slider("Contamination (expected anomalies)", 0.01, 0.30, anomaly_ratio, 0.01)

    run_analysis = st.button("🚀 Run Threat Detection", type="primary", use_container_width=True)

# Main content
if run_analysis:
    with st.spinner("🔄 Loading and analyzing security data..."):

        # Load or generate data
        if data_source == "Generate Sample Data":
            st.info(f"📊 Generating {n_samples:,} sample security events with {anomaly_ratio:.0%} anomalies...")
            data = generate_sample_data(n_samples=n_samples, anomaly_ratio=anomaly_ratio)
        else:
            if uploaded_file is not None:
                data = pd.read_csv(uploaded_file)
                st.success(f"✅ Loaded {len(data):,} events from uploaded file")
            else:
                st.error("❌ Please upload a CSV file")
                st.stop()

        # Initialize analyzer
        analyzer = ThreatAnalyzer(contamination=contamination)

        # Preprocess
        with st.spinner("🔧 Preprocessing data..."):
            analyzer.data = data
            analyzer.preprocess_data()

        # Detect threats
        with st.spinner("🤖 Running ML anomaly detection..."):
            threats = analyzer.detect_threats()
            analyzer.classify_threats()

        # Calculate metrics if ground truth available
        metrics = None
        if 'true_label' in data.columns:
            from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

            y_true = data['true_label'].values
            y_pred = analyzer.data['is_threat'].values

            precision = precision_score(y_true, y_pred)
            recall = recall_score(y_true, y_pred)
            f1 = f1_score(y_true, y_pred)
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

            metrics = {
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'tp': tp,
                'fp': fp,
                'tn': tn,
                'fn': fn
            }

    # Results Section
    st.success("✅ Analysis Complete!")

    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Events Analyzed",
            f"{len(analyzer.data):,}",
            help="Total number of security events processed"
        )

    with col2:
        threat_count = analyzer.data['is_threat'].sum()
        threat_pct = (threat_count / len(analyzer.data)) * 100
        st.metric(
            "Threats Detected",
            f"{threat_count:,}",
            f"{threat_pct:.1f}%",
            help="Number of anomalous events detected"
        )

    with col3:
        if metrics:
            st.metric(
                "Precision",
                f"{metrics['precision']:.1%}",
                help="Accuracy of threat predictions"
            )

    with col4:
        if metrics:
            st.metric(
                "Recall",
                f"{metrics['recall']:.1%}",
                help="Coverage of actual threats"
            )

    # Performance Metrics (if available)
    if metrics:
        st.divider()
        st.subheader("📊 Model Performance Metrics")

        col1, col2 = st.columns(2)

        with col1:
            # Confusion Matrix
            cm_fig = go.Figure(data=go.Heatmap(
                z=[[metrics['tn'], metrics['fp']],
                   [metrics['fn'], metrics['tp']]],
                x=['Predicted Normal', 'Predicted Threat'],
                y=['Actual Normal', 'Actual Threat'],
                text=[[f"TN: {metrics['tn']}", f"FP: {metrics['fp']}"],
                      [f"FN: {metrics['fn']}", f"TP: {metrics['tp']}"]],
                texttemplate="%{text}",
                colorscale='Blues',
                showscale=False
            ))
            cm_fig.update_layout(
                title="Confusion Matrix",
                xaxis_title="Predicted",
                yaxis_title="Actual",
                height=400
            )
            st.plotly_chart(cm_fig, use_container_width=True)

        with col2:
            # Metrics Bar Chart
            metrics_df = pd.DataFrame({
                'Metric': ['Precision', 'Recall', 'F1-Score'],
                'Value': [metrics['precision'], metrics['recall'], metrics['f1']]
            })

            metrics_fig = px.bar(
                metrics_df,
                x='Metric',
                y='Value',
                title="Performance Metrics",
                color='Value',
                color_continuous_scale='Blues',
                range_y=[0, 1]
            )
            metrics_fig.update_traces(texttemplate='%{y:.1%}', textposition='outside')
            metrics_fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(metrics_fig, use_container_width=True)

    # Visualizations
    st.divider()
    st.subheader("📈 Threat Analysis Visualizations")

    col1, col2 = st.columns(2)

    with col1:
        # Threat Score Distribution
        fig1 = px.histogram(
            analyzer.data,
            x='threat_score',
            nbins=50,
            title="Threat Score Distribution",
            labels={'threat_score': 'Threat Score', 'count': 'Frequency'},
            color_discrete_sequence=['#38bdf8']
        )
        fig1.add_vline(
            x=analyzer.data['threat_score'].mean(),
            line_dash="dash",
            line_color="red",
            annotation_text=f"Mean: {analyzer.data['threat_score'].mean():.3f}"
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        # Threat vs Normal
        threat_counts = analyzer.data['is_threat'].value_counts()
        fig2 = px.pie(
            values=threat_counts.values,
            names=['Normal', 'Threat'],
            title="Detection Results",
            color_discrete_sequence=['#22c55e', '#ef4444']
        )
        st.plotly_chart(fig2, use_container_width=True)

    # Severity Analysis
    if 'severity' in analyzer.data.columns and 'hour' in analyzer.data.columns:
        col1, col2 = st.columns(2)

        with col1:
            # Hourly Threats
            hourly_threats = analyzer.data.groupby('hour')['is_threat'].sum().reset_index()
            fig3 = px.bar(
                hourly_threats,
                x='hour',
                y='is_threat',
                title="Threat Activity by Hour",
                labels={'hour': 'Hour of Day', 'is_threat': 'Number of Threats'},
                color_discrete_sequence=['#3b82f6']
            )
            st.plotly_chart(fig3, use_container_width=True)

        with col2:
            # Severity Distribution
            severity_counts = analyzer.data[analyzer.data['is_threat']]['severity'].value_counts()
            fig4 = px.bar(
                x=severity_counts.index,
                y=severity_counts.values,
                title="Threat Severity Levels",
                labels={'x': 'Severity', 'y': 'Count'},
                color=severity_counts.index,
                color_discrete_map={'Low': '#22c55e', 'Medium': '#f59e0b', 'High': '#ef4444'}
            )
            st.plotly_chart(fig4, use_container_width=True)

    # Top Threats Table
    st.divider()
    st.subheader("⚠️ Top 10 Detected Threats")

    top_threats = analyzer.data[analyzer.data['is_threat']].nlargest(10, 'threat_score')

    display_cols = ['timestamp', 'src_ip', 'dst_port', 'threat_score', 'severity']
    available_cols = [col for col in display_cols if col in top_threats.columns]

    st.dataframe(
        top_threats[available_cols].reset_index(drop=True),
        use_container_width=True,
        hide_index=False
    )

    # Download Results
    st.divider()
    st.subheader("💾 Download Results")

    col1, col2 = st.columns(2)

    with col1:
        # Download all results
        csv_all = analyzer.data.to_csv(index=False)
        st.download_button(
            label="📥 Download All Results (CSV)",
            data=csv_all,
            file_name=f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col2:
        # Download threats only
        csv_threats = analyzer.data[analyzer.data['is_threat']].to_csv(index=False)
        st.download_button(
            label="⚠️ Download Threats Only (CSV)",
            data=csv_threats,
            file_name=f"threats_only_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

else:
    # Welcome screen
    st.info("👈 Configure settings in the sidebar and click **Run Threat Detection** to start!")

    st.markdown("""
    ### 🎯 Features:
    - **ML-Based Detection**: Isolation Forest algorithm for unsupervised anomaly detection
    - **Real-time Analysis**: Process thousands of security events in seconds
    - **Interactive Visualizations**: Explore threat patterns and distributions
    - **Performance Metrics**: Precision, recall, F1-score with confusion matrix
    - **Export Results**: Download analysis results as CSV

    ### 📊 Sample Data:
    - Generates synthetic security log data with realistic patterns
    - Includes normal traffic and simulated attack behaviors
    - Configurable event count and anomaly ratio

    ### 🚀 Get Started:
    1. Choose data source (sample or upload)
    2. Configure detection settings
    3. Click "Run Threat Detection"
    4. Explore results and download reports
    """)

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #64748b; padding: 1rem;'>
    Built with ❤️ by Kamil Nazaruk |
    <a href='https://github.com/KamilNaz/cybersecurity-threat-analysis' target='_blank'>GitHub</a> |
    <a href='https://kamilnaz.github.io' target='_blank'>Portfolio</a>
</div>
""", unsafe_allow_html=True)
