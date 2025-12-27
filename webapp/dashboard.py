import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

# Configuration
MASTER_DIR = Path("master_dataset")
OUTPUT_DIR = Path("dojo_output")
ALPACA_PATH = MASTER_DIR / "master_alpaca.json"
DPO_PATH = MASTER_DIR / "master_dpo.jsonl"
PROGRESS_DIR = OUTPUT_DIR / "progress"

st.set_page_config(
    page_title="AgenticART Dojo Dashboard",
    page_icon="🥋",
    layout="wide"
)

# --- STYLING ---
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    .gold-box { border-left: 5px solid #FFD700; padding-left: 15px; background-color: #fffdf0; margin: 10px 0; border-radius: 5px; }
    .failure-box { border-left: 5px solid #FF4B4B; padding-left: 15px; background-color: #fff5f5; margin: 10px 0; border-radius: 5px; }
    </style>
""", unsafe_allow_html=True)

# --- DATA LOADING ---
def load_json(path):
    if not path.exists():
        return []
    with open(path, "r") as f:
        return json.load(f)

def load_jsonl(path):
    if not path.exists():
        return []
    data = []
    with open(path, "r") as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data

def get_model_progress():
    if not PROGRESS_DIR.exists():
        return []
    models = []
    for p in PROGRESS_DIR.glob("*_progress.json"):
        with open(p, "r") as f:
            models.append(json.load(f))
    return models

# --- HEADER ---
st.title("🥋 AgenticART: Feedback Loopback")
st.markdown("### The Recursive Intelligence Engine")

# --- TOP METRICS ---
alpaca_data = load_json(ALPACA_PATH)
dpo_data = load_jsonl(DPO_PATH)
models = get_model_progress()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Warehouse Size", f"{len(alpaca_data)} Successes")
col2.metric("DPO Boundaries", f"{len(dpo_data)} Pairs")
col3.metric("Models Tracked", f"{len(models)}")
col4.metric("Engine Status", "Refining" if len(alpaca_data) > 0 else "Idle")

# --- MAIN CONTENT ---
tab1, tab2, tab3, tab4 = st.tabs(["🏛 The Warehouse (Exploits)", "📊 Model Progress", "🧠 DPO Intelligence", "📡 Live Monitor"])

with tab1:
    st.header("Verified 'Gold' Exploits")
    st.info("These are the highest-quality, hardware-verified commands extracted by the Refinery.")

    if not alpaca_data:
        st.warning("Warehouse is empty. Run a training session to mine data.")
    else:
        # Search filter
        search = st.text_input("🔍 Search Exploits (e.g., 'kernel', 'packages', 'pm')")

        filtered = [ex for ex in alpaca_data if search.lower() in ex['instruction'].lower() or search.lower() in ex['output'].lower()]

        for i, ex in enumerate(filtered):
            with st.container():
                title = ex['instruction'].split('\n')[0]
                st.markdown(f"#### {i+1}. {title}")
                st.markdown(f"**Task:** {ex['instruction']}")
                st.code(ex['output'], language="bash")
                st.divider()

with tab2:
    st.header("Model Progression")
    if not models:
        st.warning("No model progress data found.")
    else:
        df = pd.DataFrame(models)
        # Rename columns for display
        display_df = df[['model_id', 'current_belt_display', 'challenges_passed', 'challenges_attempted', 'pass_rate', 'average_score']]
        display_df.columns = ['Model ID', 'Belt', 'Passed', 'Attempts', 'Pass Rate %', 'Avg Score']
        st.dataframe(display_df, use_container_width=True)

        # Performance Chart
        st.subheader("Pass Rate by Model")
        st.bar_chart(df.set_index('model_id')['pass_rate'])

with tab3:
    st.header("DPO Intelligence (Boundary Learning)")
    st.info("The logic of 'Security Intuition': Comparing what failed against the Gold Standard.")

    if not dpo_data:
        st.warning("No DPO pairs generated yet.")
    else:
        for i, pair in enumerate(dpo_data[:10]): # Show last 10
            with st.container():
                st.markdown(f"##### Boundary Case {i+1}")
                st.text(pair['prompt'])
                c_col, r_col = st.columns(2)
                with c_col:
                    st.success("✅ CHOSEN (Success)")
                    st.code(pair['chosen'], language="bash")
                with r_col:
                    st.error("❌ REJECTED (Failure)")
                    st.code(pair['rejected'], language="bash")
                st.divider()

with tab4:
    st.header("📡 Live Session Monitor")
    st.info("Watching dojo_output for live training activity...")

    # Get the latest session log
    log_files = list(Path("dojo_output/training_data").glob("*_jsonl.jsonl"))
    if not log_files:
        st.warning("No live sessions active.")
    else:
        # Sort by modification time
        latest_log = max(log_files, key=os.path.getmtime)
        st.subheader(f"Latest Active Session: {latest_log.name}")

        raw_log_data = load_jsonl(latest_log)

        if not raw_log_data:
            st.write("Waiting for first attempt...")
        else:
            for entry in reversed(raw_log_data[-5:]): # Show last 5 events
                with st.expander(f"Attempt: {entry['metadata']['source_challenge_id']} - {entry['metadata']['example_type']}"):
                    st.markdown(f"**Status:** {entry['metadata']['grade']}")
                    st.markdown("**Model Output:**")
                    st.code(entry['output'], language="bash")

                    if entry['metadata']['example_type'] == "negative":
                        st.error("Failure detected in this attempt.")
                    elif entry['metadata']['example_type'] == "positive":
                        st.success("Success! Refinery has whoused this result.")

    if st.button("🛰 Scan for New Activity"):
        st.rerun()
# --- SIDEBAR ---
with st.sidebar:
    st.image("https://img.icons8.com/color/100/karate.png")
    st.header("Engine Control")

    auto_refresh = st.toggle("🛰 Auto-Refresh (10s)", value=True)
    if auto_refresh:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=10000, key="datarefresh")

    if st.button("🔄 Refresh Warehouse"):
        st.rerun()

    st.divider()
    st.subheader("Data Export")
    if alpaca_data:
        st.download_button(
            label="💾 Download Master Alpaca (SFT)",
            data=json.dumps(alpaca_data, indent=2),
            file_name="master_alpaca.json",
            mime="application/json"
        )
    if dpo_data:
        dpo_str = "\n".join([json.dumps(p) for p in dpo_data])
        st.download_button(
            label="🧠 Download Master DPO",
            data=dpo_str,
            file_name="master_dpo.jsonl",
            mime="application/jsonl"
        )
