import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Add parent directory to path for dojo imports
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from dojo.sensei.event_logger import EventLogger

    _event_logger_available = True
except ImportError:
    EventLogger = None  # type: ignore[misc,assignment]
    _event_logger_available = False

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


def safe_split(value, sep, index=0, default=""):
    """Safely split a string and return the desired part."""
    if value is None:
        return default
    try:
        return str(value).split(sep)[index]
    except (IndexError, AttributeError):
        return default


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
        model_name = safe_split(log_file.name, "_202", 0, default="UNKNOWN")

        events = load_jsonl(log_file)
        for e in events:
            if not e or not isinstance(e, dict):
                continue
            # Prefer model_id from metadata if present (future-proofing)
            meta = e.get("metadata", {})
            m = meta.get("model_id") if meta else None
            if m:
                model_name = safe_split(m, "-202", 0, default=model_name)

            e["model_id"] = model_name or "UNKNOWN"
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
    active_belt = None
    log_files = list(Path(OUTPUT_DIR / "training_data").glob("*_jsonl.jsonl"))
    if log_files:
        latest_log = max(log_files, key=os.path.getmtime)
        latest_session = latest_log.name.split("_")[0]
        raw_events = load_jsonl(latest_log)
        if raw_events:
            model_id_val = raw_events[0]["metadata"].get("model_id")
            latest_model = safe_split(model_id_val, "-202", 0, default="UNKNOWN")
            # Extract active belt from the most recent event
            active_belt = raw_events[-1]["metadata"].get("belt")

    with st.expander("ℹ️ Session Intelligence", expanded=True):
        st.write(f"**Model:** `{latest_model}`")
        st.write(f"**ID:** `{latest_session}`")
        st.write(f"**Uptime:** `{str(timedelta(seconds=int(active_sec)))}`")

    # 2. Progression
    st.divider()
    st.markdown("### 🏆 Rank & Progression")

    # Define belt emojis and labels
    belt_map = {
        "white": "⬜ WHITE",
        "yellow": "🟨 YELLOW",
        "orange": "🟧 ORANGE",
        "green": "🟩 GREEN",
        "blue": "🟦 BLUE",
        "purple": "🟪 PURPLE",
        "brown": "🟫 BROWN",
        "black": "⬛ BLACK",
    }

    count = len(alpaca_data)

    # Determine display rank: use active belt if available, otherwise use milestone-based rank
    if active_belt and active_belt.lower() in belt_map:
        rank = belt_map[active_belt.lower()]
    else:
        if count >= 40:
            rank = "🟧 ORANGE"
        elif count >= 20:
            rank = "🟨 YELLOW"
        elif count >= 10:
            rank = "⬜ WHITE"
        else:
            rank = "🥚 NOVICE"

    st.markdown(f"<div class='belt-badge'>{rank}</div>", unsafe_allow_html=True)

    # Simple progress calculation for the bar
    progress = min(count / 50, 1.0)
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

    # 4. Export Run Control
    st.divider()
    st.markdown("### 📦 Export Run")

    # Check for available event logs
    EVENT_LOG_DIR = OUTPUT_DIR / "event_logs"
    available_runs = []

    if EVENT_LOG_DIR.exists():
        for log_file in EVENT_LOG_DIR.glob("*.jsonl"):
            if log_file.name.endswith("_export.jsonl"):
                continue
            run_id = log_file.stem
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    first_line = f.readline()
                    if first_line:
                        first_event = json.loads(first_line)
                        available_runs.append(
                            {
                                "run_id": run_id,
                                "model_id": first_event.get("model_id", "unknown"),
                                "log_file": log_file,
                                "size_kb": log_file.stat().st_size / 1024,
                            }
                        )
            except (json.JSONDecodeError, KeyError):
                available_runs.append(
                    {
                        "run_id": run_id,
                        "model_id": "unknown",
                        "log_file": log_file,
                        "size_kb": log_file.stat().st_size / 1024,
                    }
                )

    if available_runs:
        run_options = [f"{r['run_id']} ({r['model_id']})" for r in available_runs]
        selected_run_idx = st.selectbox(
            "Select Run",
            range(len(run_options)),
            format_func=lambda i: run_options[i],
            help="Choose a run to export",
        )

        export_format = st.radio(
            "Format",
            ["JSONL", "Parquet", "Full Bundle"],
            horizontal=True,
            help="JSONL: line-delimited JSON | Parquet: columnar analytics | Bundle: all formats + config",
        )

        if st.button("📥 Export", use_container_width=True):
            selected_run = available_runs[selected_run_idx]
            try:
                if _event_logger_available and EventLogger is not None:
                    # Use EventLogger for proper export
                    logger = EventLogger(
                        output_dir=EVENT_LOG_DIR,
                        run_id=selected_run["run_id"],
                        model_id=selected_run["model_id"],
                    )

                    export_dir = EVENT_LOG_DIR / "exports"
                    export_dir.mkdir(parents=True, exist_ok=True)

                    if export_format == "JSONL":
                        export_path = logger.export_jsonl()
                        st.success(f"✅ Exported: {export_path.name}")

                        # Provide download button
                        jsonl_data = export_path.read_bytes()
                        st.download_button(
                            "⬇️ Download JSONL",
                            jsonl_data,
                            file_name=export_path.name,
                            mime="application/json",
                        )

                    elif export_format == "Parquet":
                        try:
                            export_path = logger.export_parquet()
                            st.success(f"✅ Exported: {export_path.name}")

                            parquet_data = export_path.read_bytes()
                            st.download_button(
                                "⬇️ Download Parquet",
                                parquet_data,
                                file_name=export_path.name,
                                mime="application/octet-stream",
                            )
                        except ImportError:
                            st.error(
                                "Parquet export requires pandas and pyarrow. "
                                "Install with: pip install pandas pyarrow"
                            )

                    else:  # Full Bundle
                        exported = logger.export_run_bundle()
                        st.success(
                            f"✅ Exported {len(exported)} files to exports/"
                        )
                        for fmt, path in exported.items():
                            st.caption(f"  • {fmt}: {path.name}")
                else:
                    st.warning("EventLogger not available. Using fallback export.")
                    # Fallback: just copy the raw log file
                    import shutil

                    export_dir = EVENT_LOG_DIR / "exports"
                    export_dir.mkdir(parents=True, exist_ok=True)
                    dest = export_dir / f"{selected_run['run_id']}_export.jsonl"
                    shutil.copy(selected_run["log_file"], dest)
                    st.success(f"✅ Copied to: {dest.name}")

            except Exception as e:
                st.error(f"Export failed: {e}")

        # Show schema documentation link
        with st.expander("📖 Schema Documentation"):
            st.markdown(
                """
**EventRecord Schema v1.0**

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | Unique run identifier |
| `model_id` | string | Model name |
| `config_hash` | string | 8-char config hash |
| `challenge_id` | string | KATA challenge ID |
| `eval_label` | enum | POSITIVE/NEGATIVE/ERROR/RECOVERY/GRADER_ERROR |
| `grade` | string | A/B/C/D/F |
| `task_tags` | array | Inferred task tags |
| `execution_success` | bool | Execution result |

**Notebook Example:**
```python
import pandas as pd
df = pd.read_parquet("run_xxx.parquet")
df.groupby("eval_label").size()
```
                """
            )
    else:
        st.info("No event logs available yet.")
        st.caption("Event logs are created when running KATA challenges with EventLogger enabled.")

    st.divider()
    selected_stage = st.radio(
        "🕹️ Stage",
        [
            "EXECUTION",
            "CURATION",
            "PLAYBOOK",
            "REINFORCEMENT",
            "METRICS",
            "BENCHMARKING",
        ],
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
recent = []
for d in discovery_data:
    try:
        ts = datetime.fromisoformat(d.get("metadata", {}).get("timestamp", ""))
        if ts > (now - timedelta(hours=1)):
            recent.append(d)
    except (ValueError, TypeError):
        continue
m1, m2, m3, m4 = st.columns(4)
m1.metric("Playbook Yield", len(alpaca_data), help="Lifetime Successes")
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
if selected_stage == "EXECUTION":
    st.subheader("📡 Execution Feed")
    st.markdown(
        "<div style='font-size:11px;color:#8b949e;margin-bottom:15px;'>"
        "<span class='status-badge badge-success'>✅ KATA</span> Training Quality | "
        "<span class='status-badge badge-success'>✨ REFINED</span> Improved | "
        "<span class='status-badge badge-fail'>❌ NEGATIVE</span> Rejected | "
        "<span class='status-badge badge-recovery'>⚠️ RECOVERY</span> Self-Heal | "
        "<span class='status-badge' style='background-color:#6e40c9;color:white;'>🔧 GRADER_ERROR</span> Infrastructure"
        "</div>",
        unsafe_allow_html=True,
    )

    # --- FILTERS ---
    if log_files:
        # Load all entries first
        raw_entries = load_jsonl(latest_log, limit=100)

        # Pre-compute eval_label for each entry
        def get_eval_label(entry):
            meta = entry.get("metadata", {})
            etype = meta.get("example_type", "unknown")
            grader_status = meta.get("grader_status", "success")
            output = str(entry.get("output", ""))

            if grader_status == "infrastructure_error" or "[ERROR:" in output:
                return "GRADER_ERROR"
            elif etype in ("positive", "kata"):
                return "POSITIVE"
            elif etype == "negative":
                return "NEGATIVE"
            elif etype == "error_recovery":
                return "RECOVERY"
            else:
                return "OTHER"

        # Add eval_label to each entry for filtering
        for entry in raw_entries:
            entry["_eval_label"] = get_eval_label(entry)

        # Get unique values for filters
        all_labels = sorted(set(e["_eval_label"] for e in raw_entries))
        all_challenge_ids = sorted(
            set(
                e.get("metadata", {}).get("source_challenge_id", "unknown")
                for e in raw_entries
            )
        )

        # Extract belt prefixes from challenge IDs
        belt_prefixes = sorted(
            set(cid.split("_")[0] for cid in all_challenge_ids if "_" in cid)
        )

        # Filter controls
        st.markdown("**🔍 Filters**")
        filter_cols = st.columns([1, 1, 2])

        with filter_cols[0]:
            selected_label = st.selectbox(
                "Eval Label", ["ALL"] + all_labels, help="Filter by evaluation result"
            )

        with filter_cols[1]:
            selected_prefix = st.selectbox(
                "KATA Prefix",
                ["ALL"] + belt_prefixes,
                help="Filter by belt/challenge prefix (e.g., white, yellow)",
            )

        with filter_cols[2]:
            command_pattern = st.text_input(
                "Command Pattern",
                placeholder="e.g., shell ip, pm path, dumpsys",
                help="Filter by command pattern in output",
            )

        st.markdown("---")

        # Apply filters
        filtered_entries = raw_entries

        if selected_label != "ALL":
            filtered_entries = [
                e for e in filtered_entries if e["_eval_label"] == selected_label
            ]

        if selected_prefix and selected_prefix != "ALL":
            filtered_entries = [
                e
                for e in filtered_entries
                if e.get("metadata", {})
                .get("source_challenge_id", "")
                .startswith(str(selected_prefix) + "_")
            ]

        if command_pattern.strip():
            pattern_lower = command_pattern.strip().lower()
            filtered_entries = [
                e
                for e in filtered_entries
                if pattern_lower in str(e.get("output", "")).lower()
                or pattern_lower in str(e.get("instruction", "")).lower()
            ]

        # Show filter results count
        st.caption(f"Showing {len(filtered_entries)} of {len(raw_entries)} entries")

        # Display filtered entries
        curr_id = None
        for entry in reversed(filtered_entries[-30:]):  # Limit display to 30
            meta = entry.get("metadata", {})
            cid = meta.get("source_challenge_id", "unknown")
            etype = meta.get("example_type", "unknown")
            grade = meta.get("grade", "?")
            eval_label = entry["_eval_label"]

            # Determine style based on eval_label
            style_map = {
                "GRADER_ERROR": ("", "background-color:#6e40c9;color:white;"),
                "POSITIVE": ("feed-refined", "background-color:#238636;color:white;"),
                "NEGATIVE": ("feed-negative", "background-color:#da3633;color:white;"),
                "RECOVERY": ("feed-recovery", "background-color:#d29922;color:black;"),
                "OTHER": ("feed-exploration", "background-color:#1f6feb;color:white;"),
            }
            style, badge_style = style_map.get(eval_label, style_map["OTHER"])

            indent = "indent-1" if cid == curr_id else ""
            curr_id = cid

            # Summary line for expander
            output_preview = str(entry.get("output", ""))[:60].replace("\n", " ")
            expander_title = f"{cid} | {eval_label} | Grade: {grade}"

            with st.expander(expander_title, expanded=False):
                # Eval Label Badge
                st.markdown(
                    f"<span class='status-badge' style='{badge_style}'>{eval_label}</span> "
                    f"<span style='color:#8b949e;'>Grade: {grade} | Type: {etype}</span>",
                    unsafe_allow_html=True,
                )

                st.markdown("---")

                # 1. Full Prompt and System Context
                st.markdown("**📝 Prompt / Instruction:**")
                instruction = entry.get("instruction", "[No instruction available]")
                st.code(instruction, language="text")

                input_context = entry.get("input", "")
                if input_context:
                    st.markdown("**🔧 Input Context:**")
                    st.code(input_context, language="text")

                st.markdown("---")

                # 2. Raw Model Output
                st.markdown("**🤖 Model Output:**")
                model_output = entry.get("output", "[No output]")
                st.code(model_output, language="bash")

                # 3. Reference Output (if available in metadata or from kata)
                reference = meta.get("reference_output") or meta.get("kata_solution")
                if reference:
                    st.markdown("**📚 Reference (Kata) Solution:**")
                    st.code(reference, language="bash")

                    # Show diff if outputs differ
                    if model_output.strip() != reference.strip():
                        st.markdown("**🔍 Diff:**")
                        st.markdown(
                            f"<pre style='background:#1a1a1a;padding:10px;border-radius:4px;font-size:11px;'>"
                            f"<span style='color:#da3633;'>- {model_output.strip()[:100]}</span>\n"
                            f"<span style='color:#238636;'>+ {reference.strip()[:100]}</span>"
                            f"</pre>",
                            unsafe_allow_html=True,
                        )
                    else:
                        st.success("✅ Output matches reference")

                # 4. Additional Metadata
                with st.container():
                    st.markdown("**📊 Metadata:**")
                    meta_cols = st.columns(3)
                    meta_cols[0].metric("Belt", meta.get("belt", "?"))
                    meta_cols[1].metric(
                        "Timestamp",
                        (
                            meta.get("timestamp", "?")[11:19]
                            if meta.get("timestamp")
                            else "?"
                        ),
                    )
                    meta_cols[2].metric(
                        "Model", safe_split(meta.get("model_id", "?"), "/", -1, "?")
                    )

elif selected_stage == "CURATION":
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

elif selected_stage == "PLAYBOOK":
    st.subheader("🏛️ Playbook")
    for i, ex in enumerate(reversed(alpaca_data)):
        first_line = safe_split(
            ex.get("instruction"), "\n", 0, default="[No Instruction]"
        )
        with st.expander(f"📜 {first_line}"):
            st.write(ex["instruction"])
            st.code(ex["output"], language="bash")

elif selected_stage == "REINFORCEMENT":
    st.subheader("🧠 Reinforcement Analytics")
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

elif selected_stage == "METRICS":
    st.subheader("📈 Performance Metrics")
    if discovery_data:
        df_a = pd.DataFrame(discovery_data)

        # Model Filter
        available_models = ["ALL"] + sorted(df_a["model_id"].unique().tolist())
        sel_model = st.selectbox("Filter by Model", available_models)
        if sel_model != "ALL":
            df_a = df_a[df_a["model_id"] == sel_model]

        df_a["dt"] = pd.to_datetime(df_a["metadata"].apply(lambda x: x["timestamp"]))
        st.markdown("#### Cumulative Playbook Yield (Last 6 Hours)")
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

elif selected_stage == "BENCHMARKING":
    st.subheader("🏁 Model Benchmarking")

    if not discovery_data:
        st.warning("No data available for comparison.")
    else:
        # Prepare Comparison DataFrame
        comp_rows = []
        for d in discovery_data:
            if not d or not isinstance(d, dict):
                continue
            cmd = d.get("output", "")
            meta = d.get("metadata", {})
            grade = meta.get("grade", "F")
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

            # --- ROW 1: PROGRESSION HEATMAP ---
            st.markdown("### 🗺️ Progression Heatmap")
            st.caption("Success rate per model across the belt curriculum")

            # Re-process discovery data to get belt information more accurately
            heatmap_rows = []
            for d in discovery_data:
                if not d or not isinstance(d, dict):
                    continue
                model = d.get("model_id", "UNKNOWN")
                if model not in selected_models:
                    continue

                meta = d.get("metadata", {})
                belt = meta.get("belt", "white").upper()
                grade = meta.get("grade", "F")
                is_success = grade in ("A", "B", "C")
                heatmap_rows.append(
                    {"Model": model, "Belt": belt, "Success": is_success}
                )

            if heatmap_rows:
                df_heat = pd.DataFrame(heatmap_rows)
                # Define belt order for axis
                belt_order = [
                    "WHITE",
                    "YELLOW",
                    "ORANGE",
                    "GREEN",
                    "BLUE",
                    "PURPLE",
                    "BROWN",
                    "BLACK",
                ]

                heat_stats = (
                    df_heat.groupby(["Model", "Belt"])["Success"].mean().reset_index()
                )
                heat_stats["Success_Rate"] = (heat_stats["Success"] * 100).fillna(0)

                base = (
                    alt.Chart(heat_stats)
                    .encode(
                        x=alt.X("Belt:N", sort=belt_order),
                        y=alt.Y("Model:N"),
                    )
                    .properties(height=300)
                )

                heatmap = base.mark_rect().encode(
                    color=alt.Color(
                        "Success_Rate:Q",
                        scale=alt.Scale(scheme="redyellowgreen"),
                        title="Pass %",
                    ),
                    tooltip=[
                        "Model",
                        "Belt",
                        alt.Tooltip("Success_Rate:Q", format=".1f"),
                    ],
                )

                # Add text labels to heatmap
                text = base.mark_text(baseline="middle").encode(
                    text=alt.Text("Success_Rate:Q", format=".0f"),
                    color=alt.condition(
                        alt.datum["Success_Rate"] > 50,
                        alt.value("black"),
                        alt.value("white"),
                    ),
                )

                st.altair_chart(heatmap + text, use_container_width=True)

            # --- ROW 2: PRIMARY METRICS ---
            st.divider()
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
                st.markdown("**Playbook Yield (Total High-Quality Examples)**")
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

            # --- ROW 3: RELIABILITY & DOMAIN ---
            st.divider()
            st.markdown("### 🏹 Reliability & Domain Expertise")
            c5, c6 = st.columns(2)

            with c5:
                st.markdown("**Stochastic vs Reliable (Retry Analysis)**")
                st.caption("How many attempts does the model need to succeed?")

                retry_data = []
                for d in discovery_data:
                    if not d or not isinstance(d, dict):
                        continue
                    model = d.get("model_id", "UNKNOWN")
                    if model not in selected_models:
                        continue
                    # Extract attempts from source_challenge_id or metadata if available
                    # For now, we simulate this based on challenge repetition in discovery log
                    meta = d.get("metadata", {})
                    grade = meta.get("grade", "F")
                    retry_data.append({"Model": model, "Grade": grade})

                df_retry = pd.DataFrame(retry_data)
                # Success on A/B is considered "Highly Reliable"
                # Success on C is "Needs Refinement"
                df_retry["Reliability"] = df_retry["Grade"].apply(
                    lambda x: (
                        "High (A/B)"
                        if x in ("A", "B")
                        else ("Medium (C)" if x == "C" else "Low (D/F)")
                    )
                )

                reliability_chart = (
                    alt.Chart(df_retry)
                    .mark_bar()
                    .encode(
                        x=alt.X("count():Q", stack="normalize", title="Distribution"),
                        y=alt.Y("Model:N"),
                        color=alt.Color(
                            "Reliability:N",
                            scale=alt.Scale(
                                domain=["High (A/B)", "Medium (C)", "Low (D/F)"],
                                range=["#238636", "#d29922", "#da3633"],
                            ),
                        ),
                        tooltip=["Model", "Reliability", "count()"],
                    )
                    .properties(height=200)
                )
                st.altair_chart(reliability_chart, use_container_width=True)

            with c6:
                st.markdown("**Domain Mastery**")
                st.caption("Net yield of 'Gold' examples by category")
                yield_cat = (
                    df_sel[df_sel["HighQuality"]]
                    .groupby(["Model", "Category"])
                    .size()
                    .reset_index(name="Gold Count")
                )

                domain_chart = (
                    alt.Chart(yield_cat)
                    .mark_bar()
                    .encode(
                        x=alt.X("Gold Count:Q"),
                        y=alt.Y("Category:N", sort="-x"),
                        color="Model:N",
                        row="Model:N",
                    )
                    .properties(height=100, width=300)
                )
                st.altair_chart(domain_chart)

            # --- ROW 4: QUALITY METRICS ---
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
