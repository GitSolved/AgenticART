"""
LLM-Pentest Web Application

Streamlit-based interface for Android penetration testing automation.
This implements the paper's web application component that bridges
PentestGPT intelligence with executable script generation.

Run with: streamlit run webapp/app.py
"""

import streamlit as st
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import LLMClient, Planner, Summarizer, ScriptGenerator
from agent.planner import PentestPhase
from agent.script_generator import ScriptType
from agent.chains import AndroidRootChain
from core.reconnaissance import ADBConnection, DeviceEnumerator
from core.exploitation import ExploitRunner
from core.exploitation.exploit_runner import ExecutionMode
from core.governance import (
    ApprovalWorkflow,
    ApprovalRequest,
    TriageLevel,
    GovernanceConfig,
    assess_triage,
    check_governance,
)
from core.traffic import MitmController, MitmConfig, MitmStatus

# Page configuration
st.set_page_config(
    page_title="LLM-Pentest",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #1e3a1e;
        border: 1px solid #2e5a2e;
    }
    .warning-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #3a3a1e;
        border: 1px solid #5a5a2e;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #3a1e1e;
        border: 1px solid #5a2e2e;
    }
    .code-output {
        font-family: 'Courier New', monospace;
        background-color: #1a1a1a;
        padding: 1rem;
        border-radius: 0.5rem;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    defaults = {
        "target_config": {
            "ip": "192.168.56.101",
            "port": "5555",
            "android_version": "13",
            "device": "Genymotion Emulator",
        },
        "llm_provider": "ollama",
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.2"),
        "ollama_models": [],
        "ollama_available": False,
        "execution_mode": "dry_run",
        "chat_history": [],
        "generated_scripts": [],
        "findings": [],
        "current_phase": "idle",
        "chain_running": False,
        # Governance & Approval
        "pending_approval": None,  # ApprovalRequest awaiting decision
        "approval_workflow": None,  # ApprovalWorkflow instance
        "approval_history": [],  # Past approval decisions
        # MITM Traffic Interception
        "mitm_controller": None,  # MitmController instance
        "mitm_status": "stopped",
        "mitm_target_package": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def refresh_ollama_models():
    """Refresh list of available Ollama models."""
    try:
        from agent.llm_client import OllamaClient
        client = OllamaClient()
        if client.is_available():
            st.session_state.ollama_available = True
            st.session_state.ollama_models = client.list_models()
        else:
            st.session_state.ollama_available = False
            st.session_state.ollama_models = []
    except Exception as e:
        st.session_state.ollama_available = False
        st.session_state.ollama_models = []


def render_sidebar():
    """Render configuration sidebar."""
    st.sidebar.title("Configuration")

    # Target Configuration
    st.sidebar.subheader("Target Device")
    st.session_state.target_config["ip"] = st.sidebar.text_input(
        "Device IP",
        value=st.session_state.target_config["ip"],
    )
    st.session_state.target_config["port"] = st.sidebar.text_input(
        "ADB Port",
        value=st.session_state.target_config["port"],
    )
    st.session_state.target_config["android_version"] = st.sidebar.selectbox(
        "Android Version",
        options=["10", "11", "12", "13", "14"],
        index=3,
    )

    # LLM Configuration
    st.sidebar.subheader("LLM Provider")
    st.session_state.llm_provider = st.sidebar.selectbox(
        "Provider",
        options=["ollama", "openai", "anthropic"],
        index=0,
        help="Ollama runs locally, free, and private",
    )

    if st.session_state.llm_provider == "ollama":
        # Check Ollama availability and list models
        if st.sidebar.button("Refresh Models", key="refresh_ollama"):
            refresh_ollama_models()

        # Show status
        if st.session_state.ollama_available:
            st.sidebar.success(f"Ollama connected")
        else:
            st.sidebar.warning("Ollama not detected")
            if st.sidebar.button("Check Connection"):
                refresh_ollama_models()

        # Model selection
        if st.session_state.ollama_models:
            model_names = [m.get("name", "unknown") for m in st.session_state.ollama_models]
            current_idx = 0
            if st.session_state.ollama_model in model_names:
                current_idx = model_names.index(st.session_state.ollama_model)

            st.session_state.ollama_model = st.sidebar.selectbox(
                "Model",
                options=model_names,
                index=current_idx,
                help="Select from your installed Ollama models",
            )
            os.environ["OLLAMA_MODEL"] = st.session_state.ollama_model
        else:
            st.session_state.ollama_model = st.sidebar.text_input(
                "Model Name",
                value=st.session_state.ollama_model,
                help="Enter model name (e.g., llama3.2, mistral, codellama)",
            )
            os.environ["OLLAMA_MODEL"] = st.session_state.ollama_model

    elif st.session_state.llm_provider == "openai":
        api_key = st.sidebar.text_input(
            "OpenAI API Key",
            type="password",
            help="Enter your OpenAI API key",
        )
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

    elif st.session_state.llm_provider == "anthropic":
        api_key = st.sidebar.text_input(
            "Anthropic API Key",
            type="password",
            help="Enter your Anthropic API key",
        )
        if api_key:
            os.environ["ANTHROPIC_API_KEY"] = api_key

    # Execution Mode
    st.sidebar.subheader("Execution Mode")
    st.session_state.execution_mode = st.sidebar.radio(
        "Mode",
        options=["dry_run", "sandboxed", "live"],
        format_func=lambda x: {
            "dry_run": "Dry Run (Safe)",
            "sandboxed": "Sandboxed",
            "live": "Live (Caution!)",
        }[x],
    )

    if st.session_state.execution_mode == "live":
        st.sidebar.warning("Live mode will execute commands on real devices!")

    # Connection Test
    st.sidebar.subheader("Connection")
    if st.sidebar.button("Test ADB Connection"):
        test_connection()


def test_connection():
    """Test ADB connection to target."""
    device_id = f"{st.session_state.target_config['ip']}:{st.session_state.target_config['port']}"
    adb = ADBConnection(device_id=device_id)

    if adb.is_connected():
        st.sidebar.success(f"Connected to {device_id}")
    else:
        st.sidebar.error(f"Failed to connect to {device_id}")


def render_main_tabs():
    """Render main content tabs."""
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Chat",
        "Script Generator",
        "Chain Runner",
        "MITM Proxy",
        "Results",
        "Governance",
    ])

    with tab1:
        render_chat_tab()

    with tab2:
        render_script_generator_tab()

    with tab3:
        render_chain_runner_tab()

    with tab4:
        render_mitm_tab()

    with tab5:
        render_results_tab()

    with tab6:
        render_governance_tab()


def render_chat_tab():
    """Render interactive chat interface."""
    st.header("PentestGPT Chat")
    st.caption("Interactive penetration testing guidance powered by LLM")

    # Display chat history
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])

    # Chat input
    if prompt := st.chat_input("Ask about Android exploitation..."):
        # Add user message
        st.session_state.chat_history.append({"role": "user", "content": prompt})

        with st.chat_message("user"):
            st.write(prompt)

        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    client = LLMClient.create(st.session_state.llm_provider)
                    system = """You are PentestGPT, an expert Android penetration testing AI.
                    Provide detailed, actionable guidance for Android security assessment.
                    Include specific commands, techniques, and safety considerations."""

                    response = client.complete(prompt, system=system)
                    st.write(response.content)

                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": response.content,
                    })
                except Exception as e:
                    st.error(f"Error: {e}")


def render_script_generator_tab():
    """Render script generation interface."""
    st.header("Script Generator")
    st.caption("Convert natural language to executable scripts")

    col1, col2 = st.columns(2)

    with col1:
        # Input
        prompt = st.text_area(
            "Describe the action to automate",
            placeholder="e.g., Extract boot image and patch with Magisk",
            height=150,
        )

        script_type = st.selectbox(
            "Script Type",
            options=["python", "bash", "adb"],
        )

        if st.button("Generate Script", type="primary"):
            if prompt:
                generate_script(prompt, script_type)
            else:
                st.warning("Please enter a description")

    with col2:
        # Output
        st.subheader("Generated Script")
        if st.session_state.generated_scripts:
            latest = st.session_state.generated_scripts[-1]
            st.code(latest["content"], language=latest["type"])

            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Save Script"):
                    save_script(latest)
            with col_b:
                if st.button("Execute Script"):
                    request_approval_for_script(latest)

        # Render approval dialog if pending
        render_approval_dialog()


def generate_script(prompt: str, script_type: str):
    """Generate script from prompt."""
    with st.spinner("Generating script..."):
        try:
            generator = ScriptGenerator()
            script = generator.generate_from_prompt(
                prompt=prompt,
                target_config=st.session_state.target_config,
                script_type=ScriptType(script_type),
            )

            # Validate
            valid, issues = generator.validate(script)

            st.session_state.generated_scripts.append({
                "name": script.name,
                "content": script.content,
                "type": script_type,
                "valid": valid,
                "issues": issues,
                "timestamp": datetime.now().isoformat(),
            })

            if not valid:
                st.warning(f"Validation issues: {issues}")

        except Exception as e:
            st.error(f"Generation failed: {e}")


def save_script(script: dict):
    """Save script to file."""
    output_dir = "scripts/generated"
    os.makedirs(output_dir, exist_ok=True)

    ext = {"python": ".py", "bash": ".sh", "adb": ".adb"}[script["type"]]
    filepath = os.path.join(output_dir, f"{script['name']}{ext}")

    with open(filepath, "w") as f:
        f.write(script["content"])

    st.success(f"Saved to: {filepath}")


def extract_commands_from_script(script_content: str, script_type: str) -> list[str]:
    """Extract executable commands from script for triage assessment."""
    commands = []
    # Patterns that indicate shell execution in Python code
    shell_patterns = ["subprocess", "Popen", "call(", "run(", "adb "]

    for line in script_content.split("\n"):
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # For bash/adb, most lines are commands
        if script_type in ("bash", "adb"):
            if not line.startswith(("if ", "then", "else", "fi", "for ", "done", "while")):
                commands.append(line)
        # For Python, look for subprocess calls
        elif script_type == "python":
            if any(pattern in line for pattern in shell_patterns):
                commands.append(line)
    return commands[:10]  # Limit to first 10 for assessment


def request_approval_for_script(script: dict):
    """Create approval request for a script before execution."""
    target = f"{st.session_state.target_config['ip']}:{st.session_state.target_config['port']}"

    # Extract commands for triage assessment
    commands = extract_commands_from_script(script["content"], script["type"])
    if not commands:
        commands = [f"Execute {script['type']} script: {script['name']}"]

    # Create approval workflow if needed
    if st.session_state.approval_workflow is None:
        st.session_state.approval_workflow = ApprovalWorkflow()

    workflow = st.session_state.approval_workflow

    # Create approval request
    request = workflow.request_approval(
        action=f"Execute {script['type']} script: {script['name']}",
        target=target,
        commands=commands,
        risk_description=f"Script contains {len(commands)} commands",
    )

    # Check if auto-approve is possible
    if workflow.should_auto_approve(request):
        st.info(f"Auto-approved (Triage Level {request.triage_level.value}: {request.triage_level.name})")
        workflow.process_approval(request, approved=True, approved_by="auto")
        execute_approved_script(script)
    else:
        # Store pending approval for UI rendering
        st.session_state.pending_approval = {
            "request": request,
            "script": script,
        }
        st.rerun()  # Refresh to show approval dialog


def execute_approved_script(script: dict):
    """Execute a script that has been approved."""
    mode = ExecutionMode(st.session_state.execution_mode)
    runner = ExploitRunner(mode=mode)

    # Save temporarily
    import tempfile
    ext = {"python": ".py", "bash": ".sh", "adb": ".sh"}[script["type"]]

    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
        f.write(script["content"])
        temp_path = f.name

    with st.spinner("Executing..."):
        result = runner.execute(temp_path)

    if result.success:
        st.success("Execution successful!")
    else:
        st.error("Execution failed")

    st.code(result.stdout or result.stderr, language="text")

    # Cleanup
    os.unlink(temp_path)


def render_approval_dialog():
    """Render the human-in-the-loop approval dialog."""
    if st.session_state.pending_approval is None:
        return

    pending = st.session_state.pending_approval
    request: ApprovalRequest = pending["request"]
    script = pending["script"]

    # Create modal-like UI with expander
    st.divider()
    st.subheader("Approval Required")

    # Governance status
    gov_passed, gov_msg = request.governance_check
    if gov_passed:
        st.success(f"Governance: {gov_msg}")
    else:
        st.error(f"Governance: {gov_msg}")

    # Triage level with color coding
    triage_colors = {
        TriageLevel.INFO: "blue",
        TriageLevel.LOW: "green",
        TriageLevel.MEDIUM: "orange",
        TriageLevel.HIGH: "red",
        TriageLevel.CRITICAL: "violet",
    }
    color = triage_colors.get(request.triage_level, "gray")
    st.markdown(f"**Triage Level:** :{color}[{request.triage_level.name} (Level {request.triage_level.value})]")

    # Action details
    st.markdown(f"**Action:** {request.action}")
    st.markdown(f"**Target:** `{request.target}`")
    st.markdown(f"**Risk:** {request.risk_description}")

    # Commands to execute
    st.markdown("**Commands:**")
    st.code("\n".join(request.commands), language="bash")

    # Script preview
    with st.expander("View Full Script"):
        st.code(script["content"], language=script["type"])

    # Approval buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Approve", type="primary", disabled=not gov_passed):
            workflow = st.session_state.approval_workflow
            workflow.process_approval(request, approved=True, approved_by="operator")
            st.session_state.approval_history.append({
                "action": request.action,
                "approved": True,
                "timestamp": datetime.now().isoformat(),
            })
            st.session_state.pending_approval = None
            execute_approved_script(script)

    with col2:
        if st.button("Reject", type="secondary"):
            workflow = st.session_state.approval_workflow
            workflow.process_approval(
                request,
                approved=False,
                approved_by="operator",
                rejection_reason="Manually rejected by operator"
            )
            st.session_state.approval_history.append({
                "action": request.action,
                "approved": False,
                "timestamp": datetime.now().isoformat(),
            })
            st.session_state.pending_approval = None
            st.warning("Execution rejected")
            st.rerun()

    with col3:
        if st.button("Cancel"):
            st.session_state.pending_approval = None
            st.rerun()

    st.divider()


def render_chain_runner_tab():
    """Render automated chain runner."""
    st.header("Android Root Chain")
    st.caption("Automated end-to-end rooting workflow")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Configuration")

        objective = st.text_input(
            "Objective",
            value="Achieve root access on target device",
        )

        max_iterations = st.slider(
            "Max Iterations",
            min_value=5,
            max_value=50,
            value=20,
        )

        require_confirmation = st.checkbox(
            "Require confirmation for actions",
            value=True,
        )

        if st.button("Start Chain", type="primary", disabled=st.session_state.chain_running):
            st.session_state.chain_running = True
            run_chain(objective, max_iterations, require_confirmation)

        if st.button("Stop Chain", disabled=not st.session_state.chain_running):
            st.session_state.chain_running = False
            st.info("Chain stopped")

    with col2:
        st.subheader("Progress")

        # Phase indicators
        phases = ["Recon", "Scan", "Exploit", "Escalate", "Verify"]
        phase_cols = st.columns(5)

        for i, phase in enumerate(phases):
            with phase_cols[i]:
                if st.session_state.current_phase == phase.lower():
                    st.markdown(f"**{phase}**")
                else:
                    st.markdown(f"_{phase}_")

        # Log output
        st.subheader("Activity Log")
        log_container = st.container()
        with log_container:
            for finding in st.session_state.findings[-10:]:
                st.text(finding)


def run_chain(objective: str, max_iterations: int, require_confirmation: bool):
    """Run the Android root chain."""
    st.info("Starting chain execution...")

    try:
        chain = AndroidRootChain(
            max_iterations=max_iterations,
            require_confirmation=require_confirmation,
        )

        # For Streamlit, we need a custom executor and callback
        def executor(script_path: str) -> str:
            mode = ExecutionMode(st.session_state.execution_mode)
            runner = ExploitRunner(mode=mode)
            result = runner.execute(script_path)
            return result.stdout if result.success else result.stderr

        def confirmation_callback(step) -> bool:
            # In a real implementation, this would show a dialog
            st.session_state.findings.append(f"[PENDING] {step.action}")
            return True  # Auto-approve for demo

        result = chain.run(
            target_config=st.session_state.target_config,
            objective=objective,
            executor=executor if st.session_state.execution_mode != "dry_run" else None,
            confirmation_callback=confirmation_callback,
        )

        if result.root_achieved:
            st.success("Root access achieved!")
        else:
            st.warning("Chain completed without achieving root")

        st.session_state.findings.extend(result.findings)

    except Exception as e:
        st.error(f"Chain failed: {e}")

    finally:
        st.session_state.chain_running = False


def render_results_tab():
    """Render results and findings."""
    st.header("Results & Findings")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("Generated Scripts")
        for script in st.session_state.generated_scripts:
            with st.expander(f"{script['name']}"):
                st.code(script["content"], language=script["type"])
                st.caption(f"Generated: {script['timestamp']}")

    with col2:
        st.subheader("Findings")
        for finding in st.session_state.findings:
            st.text(finding)

    with col3:
        st.subheader("Approval History")
        if st.session_state.approval_history:
            for entry in reversed(st.session_state.approval_history[-10:]):
                status = "Approved" if entry["approved"] else "Rejected"
                icon = "checkmark" if entry["approved"] else "x"
                st.markdown(f":{icon}: **{status}** - {entry['action'][:40]}...")
                st.caption(entry["timestamp"])
        else:
            st.info("No approval decisions yet")

    if st.button("Export Report"):
        export_report()


def render_governance_tab():
    """Render governance configuration and audit log."""
    st.header("Governance & Compliance")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Network Restrictions")
        config = GovernanceConfig()

        st.markdown("**Allowed Networks:**")
        for network in config.allowed_networks:
            st.code(network)

        # Test a target
        st.subheader("Test Target")
        test_target = st.text_input(
            "Target IP:Port",
            value=f"{st.session_state.target_config['ip']}:{st.session_state.target_config['port']}",
        )
        if st.button("Check Governance"):
            allowed, message = check_governance(test_target)
            if allowed:
                st.success(message)
            else:
                st.error(message)

    with col2:
        st.subheader("Triage Levels")
        st.markdown("""
| Level | Name | Auto-Approve |
|-------|------|--------------|
| 1 | INFO | Yes |
| 2 | LOW | Yes |
| 3 | MEDIUM | No |
| 4 | HIGH | No |
| 5 | CRITICAL | No |
        """)

        st.subheader("Test Commands")
        test_commands = st.text_area(
            "Commands (one per line)",
            placeholder="nmap -sV 192.168.1.1\nredis-cli CONFIG SET dir /tmp",
            height=100,
        )
        if st.button("Assess Triage"):
            if test_commands:
                commands = [c.strip() for c in test_commands.split("\n") if c.strip()]
                level, reason = assess_triage(commands)
                triage_colors = {
                    TriageLevel.INFO: "blue",
                    TriageLevel.LOW: "green",
                    TriageLevel.MEDIUM: "orange",
                    TriageLevel.HIGH: "red",
                    TriageLevel.CRITICAL: "violet",
                }
                color = triage_colors.get(level, "gray")
                st.markdown(f"**Result:** :{color}[{level.name} (Level {level.value})]")
                st.info(reason)

    # Audit log viewer
    st.subheader("Audit Log")
    log_dir = Path("output/logs")
    if log_dir.exists():
        log_files = sorted(log_dir.glob("audit_*.jsonl"), reverse=True)
        if log_files:
            selected_log = st.selectbox("Select log file", [f.name for f in log_files])
            if selected_log:
                log_path = log_dir / selected_log
                with open(log_path) as f:
                    entries = [json.loads(line) for line in f if line.strip()]
                if entries:
                    for entry in reversed(entries[-20:]):
                        status = "Approved" if entry.get("approved") else "Rejected"
                        st.markdown(f"**{entry['timestamp']}** - {status}: {entry['action']}")
                else:
                    st.info("Log file is empty")
        else:
            st.info("No audit logs found")
    else:
        st.info("Audit log directory not created yet")


def render_mitm_tab():
    """Render MITM proxy interface for traffic interception."""
    st.header("MITM Traffic Interception")
    st.caption("Intercept and analyze Android application traffic using mitmproxy")

    # Initialize controller if needed
    if st.session_state.mitm_controller is None:
        config = MitmConfig(
            device_ip=st.session_state.target_config["ip"],
            adb_port=int(st.session_state.target_config.get("port", "5555")),
        )
        st.session_state.mitm_controller = MitmController(config)

    controller = st.session_state.mitm_controller

    # Prerequisites Check
    with st.expander("Prerequisites Check", expanded=False):
        if st.button("Check Prerequisites"):
            checks = controller.check_prerequisites()
            for check, passed in checks.items():
                status = "ok" if passed else "missing"
                icon = ":white_check_mark:" if passed else ":x:"
                st.markdown(f"{icon} **{check.replace('_', ' ').title()}**: {status}")

    # Main controls
    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Proxy Control")

        # Status indicator
        status = controller.status
        status_colors = {
            MitmStatus.STOPPED: "red",
            MitmStatus.STARTING: "orange",
            MitmStatus.RUNNING: "green",
            MitmStatus.ERROR: "red",
        }
        st.markdown(f"**Status:** :{status_colors[status]}[{status.value.upper()}]")

        # Proxy settings
        st.text_input(
            "Listen Port",
            value=str(controller.config.listen_port),
            key="mitm_port",
            help="Port for mitmproxy to listen on",
        )

        proxy_mode = st.selectbox(
            "Interface Mode",
            options=["mitmdump", "mitmweb"],
            help="mitmdump: CLI only, mitmweb: Web UI at port 8081",
        )

        # Start/Stop buttons
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Start Proxy", type="primary", disabled=(status == MitmStatus.RUNNING)):
                with st.spinner("Starting mitmproxy..."):
                    if controller.start(mode=proxy_mode):
                        st.success("Proxy started!")
                        st.session_state.mitm_status = "running"
                        if proxy_mode == "mitmweb":
                            st.info(f"Web UI: http://localhost:{controller.config.web_port}")
                    else:
                        st.error("Failed to start proxy")

        with col_b:
            if st.button("Stop Proxy", disabled=(status != MitmStatus.RUNNING)):
                if controller.stop():
                    st.success("Proxy stopped")
                    st.session_state.mitm_status = "stopped"

        st.divider()

        # Device Configuration
        st.subheader("Device Setup")

        if st.button("Configure Device Proxy"):
            with st.spinner("Configuring proxy on device..."):
                success, msg = controller.configure_device_proxy()
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

        if st.button("Clear Device Proxy"):
            success, msg = controller.clear_device_proxy()
            if success:
                st.success(msg)
            else:
                st.error(msg)

    with col2:
        st.subheader("Certificate & Pinning Bypass")

        # Certificate installation
        with st.expander("CA Certificate Installation", expanded=True):
            st.markdown("""
            **Steps to intercept HTTPS traffic:**
            1. Start the proxy
            2. Install mitmproxy CA certificate on device
            3. Configure device to use proxy
            4. (Optional) Enable certificate pinning bypass for target app
            """)

            cert_type = st.radio(
                "Installation Type",
                options=["User Certificate", "System Certificate (Root)"],
                help="System cert survives app security checks but requires root",
            )

            if st.button("Install CA Certificate"):
                as_system = "System" in cert_type
                with st.spinner("Installing certificate..."):
                    success, msg = controller.install_ca_certificate(as_system=as_system)
                    if success:
                        st.success(msg)
                    else:
                        st.error(msg)

        # Certificate pinning bypass
        with st.expander("Certificate Pinning Bypass", expanded=True):
            st.markdown("""
            Many apps implement certificate pinning to prevent MITM attacks.
            Use Frida or objection to bypass pinning at runtime.
            """)

            st.session_state.mitm_target_package = st.text_input(
                "Target Package",
                value=st.session_state.mitm_target_package,
                placeholder="com.example.app",
                help="Package name of the app to bypass pinning for",
            )

            bypass_method = st.selectbox(
                "Bypass Method",
                options=["objection", "frida"],
                help="objection is easier, frida is more flexible",
            )

            col_c, col_d = st.columns(2)
            with col_c:
                if st.button("Start Pinning Bypass", type="secondary"):
                    if st.session_state.mitm_target_package:
                        with st.spinner(f"Starting {bypass_method} bypass..."):
                            success, msg = controller.start_pinning_bypass(
                                package=st.session_state.mitm_target_package,
                                method=bypass_method,
                            )
                            if success:
                                st.success(msg)
                            else:
                                st.error(msg)
                    else:
                        st.warning("Enter a target package name")

            with col_d:
                if st.button("Stop Bypass"):
                    if controller.stop_pinning_bypass():
                        st.success("Pinning bypass stopped")

        # Traffic display
        with st.expander("Captured Traffic", expanded=False):
            st.markdown("Recent HTTP(S) flows captured by mitmproxy")

            if st.button("Refresh Flows"):
                flows = controller.get_captured_flows(limit=20)
                if flows:
                    for flow in flows:
                        st.code(flow.get("raw", str(flow)), language="http")
                else:
                    st.info("No flows captured yet. Start the proxy and generate traffic.")

            st.markdown(f"**Flow file:** `{controller.config.flow_file}`")

    # Quick Start Guide
    st.divider()
    with st.expander("Quick Start Guide"):
        st.markdown("""
        ### Intercepting Android Traffic

        **Basic Setup:**
        ```bash
        # 1. Start mitmproxy (or use the button above)
        mitmproxy -p 8080

        # 2. Configure device proxy
        adb shell settings put global http_proxy <host_ip>:8080

        # 3. Install CA cert (first time only)
        # Push cert and install via Settings > Security
        ```

        **For Apps with Certificate Pinning:**
        ```bash
        # Use objection for easy bypass
        objection -g com.target.app explore --startup-command "android sslpinning disable"

        # Or use Frida with custom script
        frida -U -f com.target.app -l ssl_bypass.js --no-pause
        ```

        **Cleanup:**
        ```bash
        # Remove proxy when done
        adb shell settings put global http_proxy :0
        ```
        """)


def export_report():
    """Export findings as markdown report."""
    report = f"""# LLM-Pentest Report

Generated: {datetime.now().isoformat()}

## Target Configuration
- IP: {st.session_state.target_config['ip']}
- Android Version: {st.session_state.target_config['android_version']}

## Findings
"""
    for finding in st.session_state.findings:
        report += f"- {finding}\n"

    report += "\n## Generated Scripts\n"
    for script in st.session_state.generated_scripts:
        report += f"\n### {script['name']}\n```{script['type']}\n{script['content']}\n```\n"

    # Save report
    os.makedirs("output/reports", exist_ok=True)
    filepath = f"output/reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filepath, "w") as f:
        f.write(report)

    st.success(f"Report saved: {filepath}")


def main():
    """Main application entry point."""
    init_session_state()

    # Auto-check Ollama on first load
    if not st.session_state.ollama_models and st.session_state.llm_provider == "ollama":
        refresh_ollama_models()

    # Header
    st.title("LLM-Pentest")
    st.caption("LLM-Powered Android Penetration Testing Framework")

    # Render components
    render_sidebar()
    render_main_tabs()

    # Footer
    st.divider()
    st.caption("Based on 'Breaking Android with AI: A Deep Dive into LLM-Powered Exploitation'")


if __name__ == "__main__":
    main()
