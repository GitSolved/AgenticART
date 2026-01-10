"""
# AgenticART Research Dashboard (v2 - Statistical & Radar)
## "The Dojo Observatory"

Visualizes the evolution of the agent from Observer (White) to Actor (Yellow).
Features:
- Capability Radar Charts
- Statistical Significance Testing
- Multi-Model Comparison
- **Reliability Diagrams (Epistemic Calibration)**
- **Hallucination Tracking**
"""

import json
import glob
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Configuration
# output_dir defaults to "grading_output" in GradingRunner, assuming it sits in dojo root or similar.
# Adjusting path to match typical dojo structure:
METRICS_DIR = Path("dojo_output/grading_output")

st.set_page_config(
    page_title="AgenticART Research",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for "Research Grade" look
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #c9d1d9; }
    h1, h2, h3 { color: #58a6ff; font-family: 'Segoe UI', sans-serif; }
    .metric-card {
        background-color: #161b22;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #30363d;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_metrics_data():
    """Load real metrics from JSON files."""
    files = glob.glob(str(METRICS_DIR / "metrics_*.json"))
    data = []
    
    if not files:
        # Return empty structure if no files found
        return pd.DataFrame(), pd.DataFrame()

    for f in sorted(files):
        try:
            with open(f, 'r') as fp:
                content = json.load(fp)
                
                # Extract Summary Metrics
                summary = content.get("summary", {})
                scores = content.get("scores", {})
                errors = content.get("errors", {})
                reasoning = content.get("reasoning", {})
                hallucination = content.get("hallucination", {})
                calibration = content.get("calibration", {})
                
                # Timestamp from filename if not in content
                timestamp = f.split("_")[-1].replace(".json", "")
                
                # Flatten for main dataframe
                row = {
                    "File": os.path.basename(f),
                    "Timestamp": timestamp,
                    "Overall Score": summary.get("overall_score", 0) * 100,
                    "Total Graded": summary.get("total_graded", 0),
                    "False Positive Rate": errors.get("false_positive_rate", 0) * 100,
                    "Reasoning Depth": reasoning.get("avg_depth", 0) * 100,
                    "Reasoning Quality": reasoning.get("avg_quality", 0) * 100,
                    "Transferability": reasoning.get("avg_transferability", 0) * 100,
                    "Hallucination Rate": hallucination.get("rate", 0) * 100,
                    "Calibration Score": calibration.get("calibration_score", 0) * 100,
                    "ECE": calibration.get("ece", 0),
                }
                data.append(row)
        except Exception as e:
            st.error(f"Error loading {f}: {e}")
            
    df_main = pd.DataFrame(data)
    
    # Load Reliability Data (Calibration Buckets) for the latest file
    # (Or allow selection later)
    latest_file = files[-1] if files else None
    df_rel = pd.DataFrame()
    if latest_file:
        try:
            with open(latest_file, 'r') as fp:
                last_content = json.load(fp)
                buckets = last_content.get("calibration", {}).get("reliability_diagram", [])
                if buckets:
                    df_rel = pd.DataFrame(buckets)
        except:
            pass
            
    return df_main, df_rel

# --- Sidebar ---
st.sidebar.title("🔬 Dojo Observatory")
df_metrics, df_reliability = load_metrics_data()

if df_metrics.empty:
    st.warning(f"No metrics found in {METRICS_DIR}. Please run a training/grading cycle.")
    st.stop()

# Select Run to Visualize
selected_run = st.sidebar.selectbox(
    "Select Training Run", 
    df_metrics["File"].unique(), 
    index=len(df_metrics)-1
)
run_data = df_metrics[df_metrics["File"] == selected_run].iloc[0]

# --- Main ---
st.title("AgenticART Capability Evolution")
st.markdown("Quantifying the cognitive expansion from **Observation** to **Instrumentation**.")

# Top Level Metrics
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Overall Score", f"{run_data['Overall Score']:.1f}%")
with m2:
    st.metric("Reasoning Depth", f"{run_data['Reasoning Depth']:.1f}%")
with m3:
    st.metric("Calibration (1-ECE)", f"{run_data['Calibration Score']:.1f}%")
with m4:
    st.metric("Hallucination Rate", f"{run_data['Hallucination Rate']:.1f}%", delta_color="inverse")

# 1. The Capability Radar
st.subheader("1. The Capability Surface (Radar Chart)")
st.caption("Dimensions of Reasoning Quality")

categories = ["Reasoning Quality", "Reasoning Depth", "Transferability", "Overall Score", "Calibration Score"]
scores = [
    run_data["Reasoning Quality"],
    run_data["Reasoning Depth"],
    run_data["Transferability"],
    run_data["Overall Score"],
    run_data["Calibration Score"]
]
# Close the loop
scores_closed = scores + [scores[0]]
cats_closed = categories + [categories[0]]

fig_radar = go.Figure()
fig_radar.add_trace(go.Scatterpolar(
    r=scores_closed,
    theta=cats_closed,
    fill='toself',
    name='Selected Run'
))
fig_radar.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False)
st.plotly_chart(fig_radar, use_container_width=True)

# 2. Epistemic Calibration (Reliability Diagram)
st.subheader("2. Epistemic Calibration (Reliability Diagram)")
st.caption("Does the model know when it doesn't know? (Perfect calibration = Diagonal line)")

if not df_reliability.empty:
    fig_rel = go.Figure()
    
    # Perfect calibration line
    fig_rel.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode='lines', name='Perfect Calibration', line=dict(dash='dash', color='gray')))
    
    # Model calibration
    fig_rel.add_trace(go.Scatter(
        x=df_reliability["confidence"],
        y=df_reliability["accuracy"],
        mode='lines+markers',
        name='Model Reliability',
        line=dict(color='#58a6ff', width=2),
        marker=dict(size=8)
    ))
    
    # Histogram of confidence (bar chart on bottom or secondary y)
    fig_rel.add_trace(go.Bar(
        x=df_reliability["bin_center"],
        y=df_reliability["count"] / df_reliability["count"].sum(),
        name='Confidence Distribution',
        yaxis='y2',
        marker=dict(color='rgba(88, 166, 255, 0.2)')
    ))

    fig_rel.update_layout(
        xaxis_title="Confidence",
        yaxis_title="Accuracy",
        yaxis2=dict(
            title="Density",
            overlaying='y',
            side='right',
            range=[0, 1],
            showgrid=False
        ),
        legend=dict(x=0.01, y=0.99),
        height=500
    )
    st.plotly_chart(fig_rel, use_container_width=True)
else:
    st.info("No detailed calibration buckets available for this run.")

# 3. Trends over Time
st.subheader("3. Learning Trajectory")
if len(df_metrics) > 1:
    fig_trend = px.line(df_metrics, x="Timestamp", y=["Overall Score", "Hallucination Rate", "Reasoning Depth"], markers=True)
    st.plotly_chart(fig_trend, use_container_width=True)
else:
    st.markdown("*Not enough data points for trend analysis yet.*")

# 4. Stability & Variance (Stress Testing)
st.subheader("4. Stability & Variance (Stress Testing)")
st.caption("Quantifying non-deterministic behavior (Flakiness) by running the same challenge N times.")

@st.cache_data
def load_stress_test_data():
    """Load stress test results."""
    files = glob.glob(str(METRICS_DIR / "stress_test_*.json"))
    data = []
    for f in files:
        try:
            with open(f, 'r') as fp:
                content = json.load(fp)
                content['filename'] = os.path.basename(f)
                data.append(content)
        except:
            pass
    return data

stress_tests = load_stress_test_data()

if stress_tests:
    # Sidebar selection
    test_options = [f"{t['model_id']} - {t['challenge_id']} ({t['timestamp']})" for t in stress_tests]
    selected_test_idx = st.selectbox("Select Stress Test", range(len(test_options)), format_func=lambda x: test_options[x])
    test_data = stress_tests[selected_test_idx]
    
    # Metrics
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.metric("Stability Score", f"{test_data.get('stability_score', 0):.2f}", help="1.0 - (StdDev / 100)")
    with s2:
        st.metric("Pass Rate", f"{test_data.get('pass_rate', 0):.1%}")
    with s3:
        st.metric("Std Dev (Score)", f"{test_data.get('std_dev_score', 0):.1f}")
    with s4:
        st.metric("Iterations", test_data.get('iterations', 0))
        
    # Histogram of Scores
    runs = test_data.get('runs', [])
    if runs:
        scores = [r['score'] for r in runs]
        fig_hist = px.histogram(x=scores, nbins=10, labels={'x': 'Score', 'y': 'Count'}, title="Score Distribution across Iterations")
        fig_hist.update_layout(showlegend=False)
        st.plotly_chart(fig_hist, use_container_width=True)
else:
    st.info("No stress test data found. Run 'dojo/tools/stress_test.py' to generate.")

st.markdown("---")
st.markdown("**Conclusion:** The dashboard now reflects **actual** research-grade metrics from the V2 Grading Runner and Stress Testing tools.")