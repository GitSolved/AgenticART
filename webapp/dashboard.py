import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

# Move import to top to satisfy E402
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION ---
APP_DIR = Path(__file__).parent.parent
MASTER_DIR = APP_DIR / "master_dataset"
OUTPUT_DIR = APP_DIR / "dojo_output"
ALPACA_PATH = MASTER_DIR / "master_alpaca.json"
DPO_PATH = MASTER_DIR / "master_dpo.jsonl"
DISCOVERY_PATH = MASTER_DIR / "master_discovery.jsonl"
PROGRESS_DIR = OUTPUT_DIR / "progress"
ENGINE_STATE_PATH = OUTPUT_DIR / "engine_state.json"

st.set_page_config(
    page_title="AgenticART | Mission Control",
    page_icon="🥋",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENGINE STATE UTILS ---
def get_engine_state():
    if not ENGINE_STATE_PATH.exists():
        return {"status": "idle"}
    try:
        with open(ENGINE_STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"status": "unknown"}

def set_engine_state(status):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(ENGINE_STATE_PATH, "w") as f:
        json.dump({"status": status, "timestamp": datetime.now().isoformat()}, f)

# --- STYLING ---
st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 6px; border: 1px solid #30363d; }

    /* Session Header */
    .session-info {
        background-color: #161b22;
        padding: 10px 20px;
        border-radius: 8px;
        border: 1px solid #30363d;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: monospace;
        font-size: 13px;
    }
    .info-label { color: #8b949e; margin-right: 5px; }
    .info-value { color: #58a6ff; font-weight: bold; }

    /* Device Health Colors */
    .health-connected { color: #238636; font-weight: bold; }
    .health-disconnected { color: #da3633; font-weight: bold; }
    .health-unstable { color: #d29922; font-weight: bold; }

    /* Trajectory Feed Styling */
    .feed-entry {
        padding: 10px;
        border-radius: 6px;
        margin-bottom: 8px;
        border-left: 4px solid #30363d;
        background-color: #161b22;
    }
    .feed-refined { border-left-color: #238636; background-color: #1a271d; }
    .feed-negative { border-left-color: #da3633; background-color: #2d1a1a; }
    .feed-recovery { border-left-color: #d29922; background-color: #2d241a; }
    .feed-exploration { border-left-color: #1f6feb; background-color: #161b22; }

    .indent-1 { margin-left: 20px; border-left-style: dashed; }

    .icon-label { font-size: 14px; font-weight: bold; vertical-align: middle; }

    .status-badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: bold; }
    .badge-success { background-color: #238636; color: white; }
    .badge-fail { background-color: #da3633; color: white; }
    .badge-recovery { background-color: #d29922; color: black; }
    </style>
""", unsafe_allow_html=True)

# --- DATA UTILS ---
def load_json(path):
    if not path.exists():
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return []

def load_jsonl(path, limit=None):
    if not path.exists():
        return []
    data = []
    try:
        with open(path, "r") as f:
            lines = f.readlines()
            if limit:
                lines = lines[-limit:]
            for line in lines:
                if line.strip():
                    data.append(json.loads(line))
    except Exception:
        pass
    return data

def get_model_progress():
    if not PROGRESS_DIR.exists():
        return []
    models_data = []
    for p in PROGRESS_DIR.glob("*_progress.json"):
        with open(p, "r") as f:
            models_data.append(json.load(f))
    return models_data

def get_adb_status(target_serial="127.0.0.1:6562"):
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=2)
        if target_serial in result.stdout:
            if "offline" in result.stdout or "unauthorized" in result.stdout:
                return "UNSTABLE", "health-unstable"
            return "CONNECTED", "health-connected"
        return "DISCONNECTED", "health-disconnected"
    except Exception:
        return "ERROR", "health-disconnected"

# --- SIDEBAR: TARGET & SAFETY ---
with st.sidebar:
    st.image("https://img.icons8.com/color/100/security-configuration.png")
    st.title("AVR Control")

    st.markdown("### 📱 Device Health")
    status, color_class = get_adb_status()
    st.markdown(f"**ADB Status:** <span class='{color_class}'>{status}</span>", unsafe_allow_html=True)

    discovery_data = load_jsonl(DISCOVERY_PATH)
    if discovery_data:
        last_event = discovery_data[-1]
        last_ts = datetime.fromisoformat(last_event['metadata']['timestamp'])
        st.markdown(f"**Last Probe:** `{last_ts.strftime('%H:%M:%S')}`")

    st.divider()
    st.markdown("### 🛡️ Safety Rails")
    st.markdown("<span class='safety-badge'>LAB: AUTHORIZED</span><span class='safety-badge'>SELINUX: ENFORCING</span>", unsafe_allow_html=True)

    st.divider()
    selected_stage = st.radio(
        "🕹️ Select Operating Stage",
        ["STAGE 1: THE MINE", "STAGE 2: THE REFINERY", "STAGE 3: THE WAREHOUSE", "STAGE 4: THE INTELLIGENCE"],
        index=0
    )

    if st.button("🗑 Reset Engine Data", type="primary"):
        if MASTER_DIR.exists():
            shutil.rmtree(MASTER_DIR)
        if OUTPUT_DIR.exists():
            shutil.rmtree(OUTPUT_DIR)
        st.rerun()

# --- AUTO REFRESH ---
st_autorefresh(interval=5000, key="global_refresh")

# --- DATA LOADING ---
alpaca_data = load_json(ALPACA_PATH)
dpo_data = load_jsonl(DPO_PATH)

# --- HEADER & SESSION INFO ---
st.title("🥋 AgenticART: Mission Control")

# Extract Session Metadata from latest log
latest_model = "UNKNOWN"
latest_session = "IDLE"
session_duration = "00:00:00"

log_files = list(Path(OUTPUT_DIR / "training_data").glob("*_jsonl.jsonl"))
if log_files:
    latest_log = max(log_files, key=os.path.getmtime)
    latest_session = latest_log.name.split('_')[0]
    raw_events = load_jsonl(latest_log)
    if raw_events:
        latest_model = raw_events[0]['metadata'].get('model_id', 'qwen2.5-coder:32b')
        start_ts = datetime.fromisoformat(raw_events[0]['metadata']['timestamp'])
        last_ts = datetime.fromisoformat(raw_events[-1]['metadata']['timestamp'])
        duration = last_ts - start_ts
        session_duration = str(duration).split('.')[0]

st.markdown(f"""
<div class='session-info'>
    <div><span class='info-label'>LLM MODEL:</span><span class='info-value'>{latest_model}</span></div>
    <div><span class='info-label'>SESSION ID:</span><span class='info-value'>{latest_session}</span></div>
    <div><span class='info-label'>UPTIME:</span><span class='info-value'>{session_duration}</span></div>
</div>
""", unsafe_allow_html=True)

# --- GLOBAL METRICS ---
now = datetime.now()
hour_ago = now - timedelta(hours=1)
recent_discovery = [d for d in discovery_data if datetime.fromisoformat(d['metadata']['timestamp']) > hour_ago]

# Determine status_val for metric m4
engine_state = get_engine_state()
status_val = engine_state.get("status", "idle")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Warehouse Yield", len(alpaca_data), help="Total successes stored in the Gold Warehouse (Lifetime)")
m2.metric("Discovery Archive", len(discovery_data), f"+{len(recent_discovery)}" if recent_discovery else None, help="Total probes recorded in the AVR log (Lifetime). Delta shows activity in the last hour.")
m3.metric("Boundary Intelligence", len(dpo_data), help="Total DPO preference pairs generated (Lifetime)")
m4.metric("Engine Status", status_val.upper(), help="Current state of the recursive loopback engine")

st.divider()

# --- DISPLAY LOGIC BASED ON SELECTED STAGE ---
stage = selected_stage

if stage == "STAGE 1: THE MINE":
    st.subheader("📡 Hierarchical Trajectory Feed")

    # Micro Legend
    st.markdown("""
    <div style='font-size: 11px; color: #8b949e; margin-bottom: 15px; border: 1px solid #30363d; padding: 8px; border-radius: 5px; display: inline-block;'>
    <b>Legend:</b>
    <span class='status-badge badge-success'>REFINED</span> Improved Attempt |
    <span class='status-badge badge-success'>KATA</span> Training Quality |
    <span class='status-badge badge-fail'>NEGATIVE</span> Filtered Reject |
    <span class='status-badge badge-recovery'>RECOVERY</span> Self-Heal Correction
    </div>
    """, unsafe_allow_html=True)

    if not log_files:
        st.warning("Mine is idle.")
    else:
        current_challenge = None
        for event in reversed(load_jsonl(latest_log, limit=30)):
            meta = event['metadata']
            etype = meta.get('example_type', 'unknown')
            cid = meta.get('source_challenge_id', 'unknown')

            if etype in ("positive", "kata"):
                style, icon, label = "feed-refined", "✅", "REFINED"
            elif etype == "negative":
                style, icon, label = "feed-negative", "❌", "REJECTED"
            elif etype == "error_recovery":
                style, icon, label = "feed-recovery", "⚠️", "RECOVERY"
            else:
                style, icon, label = "feed-exploration", "🔍", "PROBING"

            indent = "indent-1" if cid == current_challenge else ""
            current_challenge = cid

            st.markdown(f"""
            <div class='feed-entry {style} {indent}'>
                <span class='icon-label'>{icon} {label}</span> | <b>{cid}</b>
                <br><code style='color: #8b949e;'>{event['output']}</code>
            </div>
            """, unsafe_allow_html=True)

# --- STAGE 2: THE REFINERY ---
elif stage == "STAGE 2: THE REFINERY":
    st.subheader("🧪 Quality Curation & Decision Matrix")

    if not discovery_data:
        st.info("Waiting for data...")
    else:
        # 1. Filters & Search Bar
        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            search_query = st.text_input("🔍 Search code or reason...", "")
        with c2:
            outcome_filter = st.selectbox("Filter Outcome", ["ALL", "PROMOTED", "REJECTED"])
        with c3:
            sort_order = st.selectbox("Sort By", ["Newest", "Oldest", "Belt Level", "Grade"])

        # 2. Build DataFrame
        decisions = []
        for d in discovery_data:
            grade = d['metadata']['grade']
            outcome = "PROMOTED" if grade in ("A", "B") else "REJECTED"
            decisions.append({
                "Timestamp": d['metadata']['timestamp'],
                "Belt": d['metadata']['belt'].upper(),
                "Task": d['metadata']['source_challenge_id'],
                "Grade": grade,
                "Outcome": outcome,
                "Logic": d['output']
            })
        df = pd.DataFrame(decisions)

        # 3. Apply Filtering
        if search_query:
            df = df[df['Logic'].str.contains(search_query, case=False) | df['Task'].str.contains(search_query, case=False)]
        if outcome_filter != "ALL":
            df = df[df['Outcome'] == outcome_filter]

        # 4. Apply Sorting
        if sort_order == "Newest":
            df = df.sort_values("Timestamp", ascending=False)
        elif sort_order == "Oldest":
            df = df.sort_values("Timestamp", ascending=True)
        elif sort_order == "Belt Level":
            df = df.sort_values("Belt")
        elif sort_order == "Grade":
            df = df.sort_values("Grade")

        st.dataframe(df, use_container_width=True)

# --- STAGE 3: THE WAREHOUSE ---
elif stage == "STAGE 3: THE WAREHOUSE":
    st.subheader("🏛️ Persistent Intelligence Warehouse")
    st.markdown("#### 🏆 Gold Standard Master Set (SFT)")
    st.dataframe(pd.DataFrame(alpaca_data), use_container_width=True)

# --- STAGE 4: THE INTELLIGENCE ---
elif stage == "STAGE 4: THE INTELLIGENCE":
    st.subheader("🧠 DPO Boundary Analytics")
    if not dpo_data:
        st.warning("Insufficient boundary data.")
    else:
        for i, pair in enumerate(reversed(dpo_data[-10:])):
            with st.expander(f"Boundary Analytic: {pair.get('metadata', {}).get('challenge_id', 'Exploration')}"):
                c1, c2 = st.columns(2)
                c1.success("✅ CHOSEN")
                c1.code(pair["chosen"])
                c2.error("❌ REJECTED")
                c2.code(pair["rejected"])

# --- FOOTER ---
st.divider()
st.caption(f"AgenticART Mission Control v0.4.5 | Target: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
