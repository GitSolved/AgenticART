import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
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
    initial_sidebar_state="expanded",
)


# --- ENGINE STATE UTILS ---
def get_engine_state():
    if not ENGINE_STATE_PATH.exists():
        return {"status": "idle", "accumulated_seconds": 0, "start_time": None}
    try:
        with open(ENGINE_STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"status": "unknown", "accumulated_seconds": 0, "start_time": None}


def set_engine_state(status):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    current = get_engine_state()
    accumulated = current.get("accumulated_seconds", 0)
    start_time_str = current.get("start_time")
    now = datetime.now()

    if status == "running":
        if current.get("status") != "running":
            start_time_str = now.isoformat()
    elif status in ("paused", "stopped", "idle"):
        if current.get("status") == "running" and start_time_str:
            try:
                start_time = datetime.fromisoformat(start_time_str)
                accumulated += (now - start_time).total_seconds()
            except Exception:
                pass
        start_time_str = None
        if status == "idle":
            accumulated = 0

    with open(ENGINE_STATE_PATH, "w") as f:
        json.dump(
            {
                "status": status,
                "start_time": start_time_str,
                "accumulated_seconds": accumulated,
                "last_update": now.isoformat(),
            },
            f,
        )


# --- STYLING ---
st.markdown(
    """
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 6px; border: 1px solid #30363d; }
    .session-info { background-color: #161b22; padding: 10px 20px; border-radius: 8px; border: 1px solid #30363d; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; font-family: monospace; font-size: 13px; }
    .info-label { color: #8b949e; margin-right: 5px; }
    .info-value { color: #58a6ff; font-weight: bold; }
    .belt-badge { padding: 5px 15px; border-radius: 20px; font-size: 16px; font-weight: bold; text-align: center; margin-bottom: 10px; border: 2px solid #30363d; }
    .status-badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-family: monospace; font-weight: bold; }
    .badge-success { background-color: #238636; color: white; }
    .badge-fail { background-color: #da3633; color: white; }
    .badge-recovery { background-color: #d29922; color: black; }
    .feed-entry { padding: 10px; border-radius: 6px; margin-bottom: 8px; border-left: 4px solid #30363d; background-color: #161b22; }
    .feed-refined { border-left-color: #238636; background-color: #1a271d; }
    .feed-negative { border-left-color: #da3633; background-color: #2d1a1a; }
    .feed-recovery { border-left-color: #d29922; background-color: #2d241a; }
    .feed-exploration { border-left-color: #1f6feb; background-color: #161b22; }
    .indent-1 { margin-left: 20px; border-left-style: dashed; }
    .pulse { animation: pulse-animation 2s infinite; }
    @keyframes pulse-animation { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
    </style>
    """,
    unsafe_allow_html=True,
)


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


def get_adb_status():
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=2
        )
        if "127.0.0.1:6562" in result.stdout:
            return "CONNECTED", "health-connected"
        return "DISCONNECTED", "health-disconnected"
    except Exception:
        return "ERROR", "health-disconnected"


def get_all_discovery_data():
    """Aggregate all discovery events from session logs with model mapping."""
    all_data = []
    log_files = list(Path(OUTPUT_DIR / "training_data").glob("*_jsonl.jsonl"))

    for log_file in log_files:
        # Heuristic for model name from filename
        # Format: {model_or_session}_YYYYMMDD_HHMMSS_jsonl.jsonl
        model_name = log_file.name.split("_202")[0]

        events = load_jsonl(log_file)
        for e in events:
            # Prefer model_id from metadata if present (future-proofing)
            m = e["metadata"].get("model_id")
            if m:
                model_name = m.split("-202")[0]

            e["model_id"] = model_name
            all_data.append(e)

    return all_data


# --- AUTO REFRESH ---
st_autorefresh(interval=5000, key="global_refresh")

# --- DATA LOADING ---
alpaca_data = load_json(ALPACA_PATH)
dpo_data = load_jsonl(DPO_PATH)
discovery_data = get_all_discovery_data()

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://img.icons8.com/color/100/security-configuration.png")
    st.title("AVR Control")

    # 1. Session Metadata
    engine_state = get_engine_state()
    current_status = engine_state.get("status", "idle")
    start_ts_str = engine_state.get("start_time")
    active_sec = engine_state.get("accumulated_seconds", 0)
    if current_status == "running" and start_ts_str:
        active_sec += (
            datetime.now() - datetime.fromisoformat(start_ts_str)
        ).total_seconds()

    latest_model = "UNKNOWN"
    latest_session = "IDLE"
    log_files = list(Path(OUTPUT_DIR / "training_data").glob("*_jsonl.jsonl"))
    if log_files:
        latest_log = max(log_files, key=os.path.getmtime)
        latest_session = latest_log.name.split("_")[0]
        raw_events = load_jsonl(latest_log)
        if raw_events:
            latest_model = (
                raw_events[0]["metadata"].get("model_id", "UNKNOWN").split("-202")[0]
            )

    with st.expander("ℹ️ Session Intelligence", expanded=True):
        st.write(f"**Model:** `{latest_model}`")
        st.write(f"**ID:** `{latest_session}`")
        st.write(f"**Uptime:** `{str(timedelta(seconds=int(active_sec)))}`")

    # 2. Progression
    st.divider()
    st.markdown("### 🏆 Rank & Progression")
    count = len(alpaca_data)
    if count >= 40:
        rank, progress = "🟧 ORANGE", 0.8
    elif count >= 20:
        rank, progress = "🟨 YELLOW", 0.5
    elif count >= 10:
        rank, progress = "⬜ WHITE", 0.3
    else:
        rank, progress = "🥚 NOVICE", 0.1
    st.markdown(f"<div class='belt-badge'>{rank}</div>", unsafe_allow_html=True)
    st.progress(progress)
    with st.expander("🎯 Milestones", expanded=True):
        st.write(f"Warehouse: {count}/50")
        st.progress(min(count / 50, 1.0))
        if st.button("🔍 View Discovery Archive", use_container_width=True):
            st.session_state.operating_stage_index = 2
            st.rerun()

    # 3. Controls
    st.divider()
    st.markdown("### ⚙️ Engine Control")
    if current_status == "running":
        st.success("● ACTIVE PROBING")
    elif current_status == "paused":
        st.warning("● ENGINE PAUSED")
    else:
        st.info("● IDLE")

    c1, c2 = st.columns(2)
    if current_status == "paused":
        if c1.button("▶️ Resume"):
            set_engine_state("running")
            st.rerun()
    else:
        if c1.button("⏸️ Pause"):
            set_engine_state("paused")
            st.rerun()
    if c2.button("🛑 Stop", type="primary"):
        st.session_state.confirm_stop = True

    if st.session_state.get("confirm_stop"):
        st.error("Confirm Termination?")
        if st.button("Yes, Stop"):
            set_engine_state("stopped")
            st.session_state.confirm_stop = False
            st.rerun()
        if st.button("No, Cancel"):
            st.session_state.confirm_stop = False
            st.rerun()

    st.divider()
    selected_stage = st.radio(
        "🕹️ Stage",
        ["MINE", "REFINERY", "WAREHOUSE", "INTELLIGENCE", "ANALYTICS", "COMPARISON"],
        index=st.session_state.get("operating_stage_index", 0),
    )

# --- HEADER ---
c_title, c_update = st.columns([3, 1])
with c_title:
    st.title("🥋 AgenticART: Mission Control")
with c_update:
    st.markdown(
        f"<div style='text-align:right;padding-top:20px;color:#8b949e;font-size:12px;'><span class='pulse'>📡</span> <b>LIVE FEED</b> | {datetime.now().strftime('%H:%M:%S')}</div>",
        unsafe_allow_html=True,
    )

# --- METRICS ---
now = datetime.now()
recent = [
    d
    for d in discovery_data
    if datetime.fromisoformat(d["metadata"]["timestamp"]) > (now - timedelta(hours=1))
]
m1, m2, m3, m4 = st.columns(4)
m1.metric("Warehouse Yield", len(alpaca_data), help="Lifetime Successes")
m2.metric(
    "Discovery Archive",
    len(discovery_data),
    f"+{len(recent)}" if recent else None,
    help="Lifetime Probes",
)
m3.metric("Boundary Intel", len(dpo_data), help="Lifetime DPO Pairs")
m4.metric("Engine Status", current_status.upper())
st.divider()

# --- DISPLAY LOGIC ---
if selected_stage == "MINE":
    st.subheader("📡 Trajectory Feed")
    st.markdown(
        "<div style='font-size:11px;color:#8b949e;margin-bottom:15px;'><span class='status-badge badge-success'>✅ KATA</span> Training Quality | <span class='status-badge badge-success'>✨ REFINED</span> Improved | <span class='status-badge badge-fail'>❌ NEGATIVE</span> Rejected | <span class='status-badge badge-recovery'>⚠️ RECOVERY</span> Self-Heal</div>",
        unsafe_allow_html=True,
    )
    if log_files:
        curr_id = None
        for e in reversed(load_jsonl(latest_log, limit=30)):
            meta = e["metadata"]
            cid = meta.get("source_challenge_id", "unknown")
            etype = meta.get("example_type", "unknown")
            style = {
                "positive": "feed-refined",
                "kata": "feed-refined",
                "negative": "feed-negative",
                "error_recovery": "feed-recovery",
            }.get(etype, "feed-exploration")
            indent = "indent-1" if cid == curr_id else ""
            curr_id = cid
            st.markdown(
                f"<div class='feed-entry {style} {indent}'><b>{cid}</b> | {etype.upper()}<br><code>{e['output']}</code></div>",
                unsafe_allow_html=True,
            )

elif selected_stage == "REFINERY":
    st.subheader("🧪 Quality Curation")
    st.markdown(
        "<div style='font-size:11px;color:#8b949e;margin-bottom:15px;'>A=Perfect, B=Minor, C=Marginal, D=Poor, F=Failed</div>",
        unsafe_allow_html=True,
    )
    c1, c2 = st.columns([2, 1])
    query = c1.text_input("🔍 Search...")
    out_f = c2.selectbox("Filter", ["ALL", "PROMOTED", "REJECTED"])
    df = pd.DataFrame(
        [
            {
                "Time": d["metadata"]["timestamp"][11:19],
                "Task": d["metadata"]["source_challenge_id"],
                "Grade": d["metadata"]["grade"],
                "Outcome": (
                    "PROMOTED" if d["metadata"]["grade"] in ("A", "B") else "REJECTED"
                ),
                "Logic": d["output"],
            }
            for d in discovery_data
        ]
    )
    if not df.empty:
        if out_f != "ALL":
            df = df[df["Outcome"] == out_f]
        if query:
            df = df[df["Logic"].str.contains(query, case=False)]
        st.dataframe(df.sort_values("Time", ascending=False), use_container_width=True)

elif selected_stage == "WAREHOUSE":
    st.subheader("🏛️ Gold Warehouse")
    for i, ex in enumerate(reversed(alpaca_data)):
        first_line = ex["instruction"].split("\n")[0]
        with st.expander(f"📜 {first_line}"):
            st.write(ex["instruction"])
            st.code(ex["output"], language="bash")

elif selected_stage == "INTELLIGENCE":
    st.subheader("🧠 Boundary Analytics")
    for p in reversed(dpo_data[-10:]):
        with st.expander(
            f"Boundary: {p.get('metadata', {}).get('challenge_id', 'Exploration')}"
        ):
            st.write(
                f"Source: {p.get('signal_source', 'N/A')} | Margin: {p.get('margin', 0.0)}"
            )
            c1, c2 = st.columns(2)
            c1.success("✅ CHOSEN")
            c1.code(p["chosen"])
            c2.error("❌ REJECTED")
            c2.code(p["rejected"])

elif selected_stage == "ANALYTICS":
    st.subheader("📈 Performance Analytics")
    if discovery_data:
        df_a = pd.DataFrame(discovery_data)

        # Model Filter
        available_models = ["ALL"] + sorted(df_a["model_id"].unique().tolist())
        sel_model = st.selectbox("Filter by Model", available_models)
        if sel_model != "ALL":
            df_a = df_a[df_a["model_id"] == sel_model]

        df_a["dt"] = pd.to_datetime(df_a["metadata"].apply(lambda x: x["timestamp"]))
        st.markdown("#### Cumulative Warehouse Yield (Last 6 Hours)")
        l6 = df_a[df_a["dt"] > (now - timedelta(hours=6))].copy()
        if not l6.empty:
            l6["is_success"] = l6["metadata"].apply(
                lambda x: 1 if x["grade"] in ("A", "B") else 0
            )
            l6 = l6.sort_values("dt")
            l6["cum"] = l6["is_success"].cumsum()
            st.line_chart(l6.set_index("dt")["cum"])
        ca, cb = st.columns(2)
        with ca:
            st.markdown("#### Probe Rate (Probes/Min)")
            st.area_chart(l6.resample("1min", on="dt").count()["output"])
        with cb:
            st.markdown("#### Outcome Ratio (Hourly)")
            l6["Outcome"] = l6["metadata"].apply(
                lambda x: "PROMOTED" if x["grade"] in ("A", "B") else "REJECTED"
            )
            st.bar_chart(
                l6.groupby([pd.Grouper(key="dt", freq="1h"), "Outcome"])
                .size()
                .unstack(fill_value=0)
            )

        # --- COMMAND BREAKDOWN ---
        st.divider()
        st.subheader("🧩 Command Category Breakdown")

        # Prepare Data
        cmd_data = []
        for d in discovery_data:
            cmd = d.get("output", "")
            grade = d["metadata"].get("grade", "F")
            is_success = grade in ("A", "B")

            # Classification
            cat = "Other"
            c_low = cmd.lower()
            if any(x in c_low for x in ["frida", "objection", "spawn", "attach"]):
                cat = "Frida Hooks"
            elif any(x in c_low for x in ["adb", "pm ", "am ", "dumpsys", "input"]):
                cat = "ADB Commands"
            elif any(
                x in c_low for x in ["cat ", "ls ", "cd ", "find ", "grep ", "chmod"]
            ):
                cat = "File Access"
            elif any(
                x in c_low
                for x in ["curl", "wget", "ping", "netstat", "ip ", "nc ", "nmap"]
            ):
                cat = "Network"

            cmd_data.append({"Category": cat, "Command": cmd, "Success": is_success})

        df_cmd = pd.DataFrame(cmd_data)

        if not df_cmd.empty:
            c1, c2 = st.columns([1, 1])

            with c1:
                st.markdown("**Attack Distribution**")
                pie_chart = (
                    alt.Chart(df_cmd)
                    .mark_arc(innerRadius=50)
                    .encode(
                        theta=alt.Theta("count()", stack=True),
                        color=alt.Color("Category"),
                        tooltip=["Category", "count()"],
                    )
                )
                st.altair_chart(pie_chart, use_container_width=True)

            with c2:
                st.markdown("**Success Rate Heatmap**")
                # Calculate success rates
                stats = (
                    df_cmd.groupby("Category")
                    .agg(
                        Attempts=("Success", "count"), Success_Rate=("Success", "mean")
                    )
                    .reset_index()
                )

                # Formatted dataframe for heatmap-like display
                st.dataframe(
                    stats.style.format({"Success_Rate": "{:.1%}"}).background_gradient(
                        subset=["Success_Rate"], cmap="RdYlGn"
                    ),
                    use_container_width=True,
                )

            st.markdown("**🏆 Top 5 Most Attempted Commands**")
            top_cmds = df_cmd["Command"].value_counts().head(5).reset_index()
            top_cmds.columns = ["Command", "Attempts"]
            st.table(top_cmds)

elif selected_stage == "COMPARISON":
    st.subheader("🏁 Model Benchmarking & Comparison")

    if not discovery_data:
        st.warning("No data available for comparison.")
    else:
        # Prepare Comparison DataFrame
        comp_rows = []
        for d in discovery_data:
            cmd = d.get("output", "")
            grade = d["metadata"].get("grade", "F")
            model = d.get("model_id", "UNKNOWN")
            is_success = grade in ("A", "B", "C")  # passing grade
            is_high_quality = grade in ("A", "B")  # gold/refined

            # Classification
            cat = "Other"
            c_low = cmd.lower()
            if any(x in c_low for x in ["frida", "objection", "spawn", "attach"]):
                cat = "Frida Hooks"
            elif any(x in c_low for x in ["adb", "pm ", "am ", "dumpsys", "input"]):
                cat = "ADB Commands"
            elif any(
                x in c_low for x in ["cat ", "ls ", "cd ", "find ", "grep ", "chmod"]
            ):
                cat = "File Access"
            elif any(
                x in c_low
                for x in ["curl", "wget", "ping", "netstat", "ip ", "nc ", "nmap"]
            ):
                cat = "Network"

            comp_rows.append(
                {
                    "Model": model,
                    "Category": cat,
                    "Success": is_success,
                    "HighQuality": is_high_quality,
                    "Grade": grade if grade else "N/A",
                }
            )

        df_comp = pd.DataFrame(comp_rows)
        all_models = sorted(df_comp["Model"].unique())

        selected_models = st.multiselect(
            "Select Models to Compare", all_models, default=all_models[:3]
        )

        if selected_models:
            df_sel = df_comp[df_comp["Model"].isin(selected_models)]

            # --- ROW 1: PRIMARY METRICS ---
            st.markdown("### 📊 Performance Benchmarking")
            c1, c2 = st.columns(2)

            with c1:
                st.markdown("**Success Rate (%)**")
                success_stats = df_sel.groupby("Model")["Success"].mean().reset_index()
                success_stats["Success"] *= 100
                chart = (
                    alt.Chart(success_stats)
                    .mark_bar()
                    .encode(
                        x=alt.X("Model:N", sort="-y"),
                        y=alt.Y("Success:Q", title="Success Rate %"),
                        color="Model:N",
                        tooltip=["Model", alt.Tooltip("Success:Q", format=".1f")],
                    )
                    .properties(height=300)
                )
                st.altair_chart(chart, use_container_width=True)

            with c2:
                st.markdown("**Warehouse Yield (Total High-Quality Examples)**")
                yield_stats = df_sel.groupby("Model")["HighQuality"].sum().reset_index()
                chart = (
                    alt.Chart(yield_stats)
                    .mark_bar()
                    .encode(
                        x=alt.X("Model:N", sort="-y"),
                        y=alt.Y("HighQuality:Q", title="Examples Generated"),
                        color="Model:N",
                        tooltip=["Model", "HighQuality"],
                    )
                    .properties(height=300)
                )
                st.altair_chart(chart, use_container_width=True)

            # --- ROW 2: CATEGORY OPTIMIZATION ---
            st.divider()
            st.markdown("### 🎯 Task-Specification Optimization")
            st.caption("Identify which models excel at specific categories")

            cat_stats = (
                df_sel.groupby(["Model", "Category"])["Success"].mean().reset_index()
            )
            cat_stats["Success"] *= 100

            chart = (
                alt.Chart(cat_stats)
                .mark_bar()
                .encode(
                    x=alt.X("Model:N", title=None),
                    y=alt.Y("Success:Q", title="Success Rate %"),
                    color="Model:N",
                    column=alt.Column("Category:N", title="Command Category"),
                    tooltip=[
                        "Model",
                        "Category",
                        alt.Tooltip("Success:Q", format=".1f"),
                    ],
                )
                .properties(width=150, height=250)
            )
            st.altair_chart(chart)

            # --- ROW 3: QUALITY METRICS ---
            st.divider()
            st.markdown("### 🧪 Quality Distributions")

            c3, c4 = st.columns([2, 1])

            with c3:
                st.markdown("**Grade Distribution**")
                grade_dist = (
                    df_sel.groupby(["Model", "Grade"]).size().reset_index(name="Count")
                )
                chart = (
                    alt.Chart(grade_dist)
                    .mark_bar()
                    .encode(
                        x=alt.X("Model:N"),
                        y=alt.Y("Count:Q", stack="normalize", title="Ratio"),
                        color=alt.Color(
                            "Grade:N",
                            scale=alt.Scale(
                                domain=["A", "B", "C", "D", "F", "N/A"],
                                range=[
                                    "#238636",
                                    "#2ea043",
                                    "#8b949e",
                                    "#d29922",
                                    "#da3633",
                                    "#30363d",
                                ],
                            ),
                        ),
                        tooltip=["Model", "Grade", "Count"],
                    )
                    .properties(height=300)
                )
                st.altair_chart(chart, use_container_width=True)

            with c4:
                st.markdown("**Promotion vs Rejection Ratio**")
                prom_stats = df_sel.copy()
                prom_stats["Outcome"] = prom_stats["HighQuality"].apply(
                    lambda x: "PROMOTED" if x else "REJECTED"
                )
                prom_dist = (
                    prom_stats.groupby(["Model", "Outcome"])
                    .size()
                    .reset_index(name="Count")
                )
                chart = (
                    alt.Chart(prom_dist)
                    .mark_bar()
                    .encode(
                        x=alt.X("Model:N"),
                        y=alt.Y("Count:Q", stack="normalize"),
                        color=alt.Color(
                            "Outcome:N",
                            scale=alt.Scale(
                                domain=["PROMOTED", "REJECTED"],
                                range=["#238636", "#da3633"],
                            ),
                        ),
                        tooltip=["Model", "Outcome", "Count"],
                    )
                    .properties(height=300)
                )
                st.altair_chart(chart, use_container_width=True)

st.divider()
st.caption(
    f"AgenticART Mission Control v0.4.5 | Target: {datetime.now().strftime('%Y-%m-%d')}"
)
