#!/usr/bin/env python3
"""
AgenticART Curriculum Trainer (v5 - Yellow Belt Expansion)

Features:
- Full 12-Target Curriculum (White + Yellow)
- Strict Schema Alignment (Action JSON) for ALL challenges
- Curriculum Learning Ready
"""

import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# --- Randomization Pools ---

PACKAGES = [
    "com.example.service", "com.bank.app", "org.chat.secure", "com.social.media",
    "io.wallet.crypto", "net.vpn.client", "com.health.tracker", "com.game.engine",
    "com.android.systemui", "com.google.android.gms", "com.samsung.android.security"
]

SERVICES = [
    "AuthService", "PaymentService", "LocationProvider", "SyncAdapter",
    "CryptoManager", "NetworkMonitor", "AnalyticsCollector", "UpdateService"
]

LOG_MESSAGES = [
    "System Healthy", "User Authenticated", "Connection Established",
    "Token Refreshed", "Database Compacted", "Config Loaded",
    "Heartbeat Received", "Binder Transaction Complete"
]

INTENT_ACTIONS = [
    "android.intent.action.VIEW", "android.intent.action.SEND",
    "com.example.action.DEBUG", "com.example.action.LOGIN"
]

API_KEYS = [
    "sk_live_8899aabbcc", "pk_test_123456", "ghp_secrettoken99", "aws_access_key_id"
]

CREDS_FILES = ["user_creds.xml", "auth_token.xml", "session.xml", "config_prefs.xml"]
LIFECYCLE_METHODS = ["onCreate", "onNewIntent", "onResume", "onStart"]
SQLITE_TABLES = ["secrets", "users", "credentials", "config", "messages"]

# --- Data Structures ---

@dataclass
class MicroTask:
    id: str
    goal: str
    command_template: str
    output_template: str
    thought_template: str

@dataclass
class ChallengeTemplate:
    id: str
    title: str
    description: str
    micro_tasks: List[MicroTask]
    output_schema: Dict[str, Any]

@dataclass
class GeneratedInstance:
    challenge_id: str
    variables: Dict[str, Any]
    trajectory: str
    final_output: str
    ground_truth: Dict[str, Any]

# --- Challenge Definitions (12 Targets) ---

CHALLENGES = [
    # --- WHITE BELT (Foundations) ---
    ChallengeTemplate(
        id="ch1_black_box",
        title="The Black Box (Process Model)",
        description="Identify the process emitting a specific log message.",
        micro_tasks=[
            MicroTask(
                id="1a",
                goal="Identify emitting PID",
                thought_template="I need to find the PID associated with the log message '{log_msg}'.",
                command_template="adb logcat -d | grep '{log_msg}' | head -1",
                output_template="[10-24 14:32:01.450 {pid}:1256 D/Tag] {log_msg}"
            ),
            MicroTask(
                id="1b",
                goal="Map PID to Process",
                thought_template="Now I verify the PID {pid} to find its process name and UID.",
                command_template="adb shell ps -A | grep {pid}",
                output_template="u0_a{uid} {pid} 1 123456 12345 0 {package}"
            )
        ],
        output_schema={
            "command": "adb shell ps -A | grep {pid}",
            "expected_output": "{package}",
            "confidence": 0.98,
            "evidence_type": "Process List Verification"
        }
    ),
    ChallengeTemplate(
        id="ch2_open_door",
        title="The Open Door (Manifest Analysis)",
        description="Identify and verify exported components.",
        micro_tasks=[
            MicroTask(
                id="2a",
                goal="Decompile Manifest",
                thought_template="I need to check the manifest of {package} for exported activities.",
                command_template="apktool d {package}.apk -o decoded && grep -B 2 'exported=\"true\"' decoded/AndroidManifest.xml",
                output_template='<activity android:name="{component}" exported="true">'
            ),
            MicroTask(
                id="2b",
                goal="Verify Runtime Export",
                thought_template="Manifest says exported, but I must verify runtime status with dumpsys.",
                command_template="adb shell dumpsys package {package} | grep -A 5 '{component}'",
                output_template="Activity {package}/.{component}\n    exported=true"
            )
        ],
        output_schema={
            "command": "adb shell dumpsys package {package} | grep -A 5 '{component}'",
            "expected_output": "exported=true",
            "confidence": 0.99,
            "evidence_type": "Runtime Dumpsys Verification"
        }
    ),
    ChallengeTemplate(
        id="ch3_unchecked_messenger",
        title="The Unchecked Messenger (Lifecycle)",
        description="Identify logic bypass via lifecycle transitions.",
        micro_tasks=[
            MicroTask(
                id="3a",
                goal="Static Analysis",
                thought_template="Checking lifecycle method overrides.",
                command_template="jadx -d out {package}.apk && grep -r 'onCreate' out/",
                output_template="{component}.onCreate(): checkPin()"
            ),
            MicroTask(
                id="3b",
                goal="Dynamic Trace",
                thought_template="Tracing execution order.",
                command_template="frida-trace -U -f {package} -i '*{component}.*'",
                output_template="{component}.{lifecycle_method} called (skipping onCreate)"
            )
        ],
        output_schema={
            "command": "frida-trace -U -f {package} -i '*{component}.*'",
            "expected_output": "{lifecycle_method} called",
            "confidence": 0.95,
            "evidence_type": "Dynamic Lifecycle Trace"
        }
    ),
    ChallengeTemplate(
        id="ch4_glass_house",
        title="The Glass House (Static Secrets)",
        description="Find the hardcoded API Key inside the compiled APK code.",
        micro_tasks=[
            MicroTask(
                id="4a",
                goal="Search Source",
                thought_template="Searching decompiled source code for common secret patterns.",
                command_template="grep -r 'API_KEY' out/",
                output_template='private static final String API_KEY = "{api_key}";'
            )
        ],
        output_schema={
            "command": "grep -r '{api_key}' out/",
            "expected_output": "{api_key}",
            "confidence": 1.0,
            "evidence_type": "Source Code Artifact"
        }
    ),
    ChallengeTemplate(
        id="ch5_open_diary",
        title="The Open Diary (Insecure Storage)",
        description="Locate plaintext credentials in the app's private data.",
        micro_tasks=[
            MicroTask(
                id="5a",
                goal="Inspect Storage",
                thought_template="Checking shared preferences for sensitive data.",
                command_template="adb shell ls -R /data/data/{package}/shared_prefs",
                output_template="{creds_file}"
            ),
            MicroTask(
                id="5b",
                goal="Read Content",
                thought_template="Reading the content of the preference file.",
                command_template="adb shell cat /data/data/{package}/shared_prefs/{creds_file}",
                output_template='<string name="password">{token}</string>'
            )
        ],
        output_schema={
            "command": "adb shell cat /data/data/{package}/shared_prefs/{creds_file}",
            "expected_output": "{token}",
            "confidence": 1.0,
            "evidence_type": "Filesystem Artifact"
        }
    ),

    # --- YELLOW BELT (Dynamic Analysis & Causality) ---

    # CH7: The Leaky Bucket
    ChallengeTemplate(
        id="ch7_leaky_bucket",
        title="The Invisible Hand (Frida Basics)",
        description="Hook a boolean return value to bypass a check.",
        micro_tasks=[
            MicroTask(
                id="7a",
                goal="Identify Check",
                thought_template="Locating isAdmin() method.",
                command_template="grep -r 'isAdmin' out/",
                output_template="boolean isAdmin() { return false; }"
            ),
            MicroTask(
                id="7b",
                goal="Hook Return",
                thought_template="Overwriting implementation to return true.",
                command_template="frida -U -f {package} -l script.js",
                output_template="Admin Access Granted"
            )
        ],
        output_schema={
            "command": "frida -U -f {package} -l script.js",
            "script_content": "Java.perform(() => {{ Class.use('{package}.AdminPanel').isAdmin.implementation = () => true; }});",
            "expected_output": "Admin Access Granted",
            "confidence": 1.0,
            "evidence_type": "Runtime Bypass"
        }
    ),

    # CH8: The Implicit Trust (Renamed to Locked Vault per Yellow Belt MD)
    ChallengeTemplate(
        id="ch8_locked_vault",
        title="The Locked Vault (Argument Modification)",
        description="Hook a method to brute-force or steal arguments.",
        micro_tasks=[
            MicroTask(
                id="8a",
                goal="Identify Target",
                thought_template="Finding checkPin method.",
                command_template="jadx -d out {package}.apk",
                output_template="boolean checkPin(String input)"
            ),
            MicroTask(
                id="8b",
                goal="Spy on Arguments",
                thought_template="Hooking method to log arguments.",
                command_template="frida -U -f {package} -l logger.js",
                output_template="PIN: {token}"
            )
        ],
        output_schema={
            "command": "frida -U -f {package} -l logger.js",
            "script_content": "overload('java.lang.String').implementation = function(a) {{ console.log('PIN:', a); return this.checkPin(a); }}",
            "expected_output": "{token}",
            "confidence": 1.0,
            "evidence_type": "Argument Leak"
        }
    ),

    # CH9: The Secret Messenger (Renamed from Race Condition per Yellow Belt MD order? No, MD has Ch9 as Secret Messenger)
    # Checking MD: Ch9 is Secret Messenger (Traffic). Ch10 is Stubborn Guard (Pinning). Ch11 is Native.
    # The V5 trainer had Ch9 as Race Condition. I must re-order to match MD.

    ChallengeTemplate(
        id="ch9_secret_messenger",
        title="The Secret Messenger (Traffic Interception)",
        description="Intercept HTTP traffic using a Proxy.",
        micro_tasks=[
            MicroTask(
                id="9a",
                goal="Configure Proxy",
                thought_template="Setting up mitmproxy.",
                command_template="mitmproxy --mode transparent",
                output_template="Proxy listening"
            ),
            MicroTask(
                id="9b",
                goal="Capture Traffic",
                thought_template="Analyzing POST requests.",
                command_template="cat proxy.log",
                output_template="POST /api/flag"
            )
        ],
        output_schema={
            "command": "mitmproxy",
            "captured_request": "POST /api/flag",
            "captured_data": "flag{{network_intercepted}}",
            "confidence": 1.0,
            "evidence_type": "Traffic Dump"
        }
    ),

    # CH10: The Stubborn Guard (SSL Pinning)
    ChallengeTemplate(
        id="ch10_stubborn_guard",
        title="The Stubborn Guard (SSL Pinning)",
        description="Bypass Certificate Pinning.",
        micro_tasks=[
            MicroTask(
                id="10a",
                goal="Identify Pinning",
                thought_template="App fails connection with proxy.",
                command_template="adb logcat | grep 'CertificateException'",
                output_template="TrustAnchor not found"
            ),
            MicroTask(
                id="10b",
                goal="Bypass",
                thought_template="Disabling TrustManager.",
                command_template="objection explore --startup-command 'android sslpinning disable'",
                output_template="Pinning disabled"
            )
        ],
        output_schema={
            "command": "objection explore --startup-command 'android sslpinning disable'",
            "verification": "Traffic visible in proxy",
            "confidence": 1.0,
            "evidence_type": "Pinning Bypass"
        }
    ),

    # CH11: The Native Wall
    ChallengeTemplate(
        id="ch11_native_wall",
        title="The Native Wall (Native Hooks)",
        description="Hook a JNI function in a .so library.",
        micro_tasks=[
            MicroTask(
                id="11a",
                goal="Find Symbol",
                thought_template="Listing symbols in libnative.so.",
                command_template="nm -D libnative.so | grep check_license",
                output_template="T Java_com_example_kappa_NativeLib_checkLicense"
            ),
            MicroTask(
                id="11b",
                goal="Native Hook",
                thought_template="Attaching to native address.",
                command_template="frida -U -f {package} -l native.js",
                output_template="License Check Bypassed"
            )
        ],
        output_schema={
            "command": "frida -U -f {package} -l native.js",
            "script_content": "Interceptor.attach(Module.getExportByName('libnative.so', 'check_license'), ...)",
            "evidence_type": "Native Bypass",
            "confidence": 0.95
        }
    )
]

# --- Generator Engine ---

class ReActGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_variables(self) -> Dict[str, Any]:
        pkg = random.choice(PACKAGES)
        service = random.choice(SERVICES)
        return {
            "package": pkg,
            "pid": str(random.randint(1000, 9999)),
            "uid": str(random.randint(10000, 10999)),
            "service_short": service,
            "service_full": f"{pkg}.{service}",
            "interface": f"{pkg}.I{service}",
            "log_msg": random.choice(LOG_MESSAGES),
            "component": f"{service}Activity",
            "action": random.choice(INTENT_ACTIONS),
            "lifecycle_method": random.choice(LIFECYCLE_METHODS),
            "token": str(uuid.uuid4())[:8],
            "api_key": random.choice(API_KEYS),
            "creds_file": random.choice(CREDS_FILES),
            "table": random.choice(SQLITE_TABLES),
            "delta_ms": random.randint(5, 50)
        }

    def fill_template(self, template: str, vars: Dict[str, Any]) -> str:
        try:
            return template.format(**vars)
        except KeyError:
            return template

    def create_instance(self, challenge: ChallengeTemplate) -> GeneratedInstance:
        vars = self.generate_variables()
        trajectory_lines = []
        for task in challenge.micro_tasks:
            thought = self.fill_template(task.thought_template, vars)
            cmd = self.fill_template(task.command_template, vars)
            obs = self.fill_template(task.output_template, vars)
            trajectory_lines.append(f"Thought: {thought}")
            trajectory_lines.append(f"Action: {cmd}")
            trajectory_lines.append(f"Observation: {obs}")
        trajectory_text = "\n".join(trajectory_lines)

        filled_schema = {}
        for k, v in challenge.output_schema.items():
            if isinstance(v, str):
                filled_schema[k] = self.fill_template(v, vars)
            else:
                filled_schema[k] = v
        final_json = json.dumps(filled_schema, indent=2)

        return GeneratedInstance(challenge.id, vars, trajectory_text, final_json, vars)

    def create_rejected_instance(self, challenge: ChallengeTemplate, vars: Dict[str, Any]) -> str:
        """Create a 'lazy' or 'blind activism' response for DPO rejection."""
        # 1. Skip the trajectory headers (Lazy)
        # 2. Use vague commands (Blind Activism)
        # 3. Use wrong JSON format (Schema Drift)

        lazy_thought = f"I need to check {vars['package']}."
        # Generate a vague/bad command based on the challenge type
        if "sql" in challenge.id:
            bad_cmd = "sql injection"
        elif "frida" in challenge.id:
            bad_cmd = "frida -U -f com.app" # Missing script
        elif "adb" in challenge.id:
            bad_cmd = "adb shell ls" # Generic
        else:
            bad_cmd = "run exploit"

        bad_response = f"""Thought: {lazy_thought}
Action: {bad_cmd}
Observation: Command failed.

Answer: {{ "result": "vulnerable" }}
"""
        return bad_response

    def format_for_dpo(self, instance: GeneratedInstance, challenge: ChallengeTemplate) -> Dict[str, Any]:
        """Format as DPO training pair."""
        prompt = f"""User: Analyze {instance.variables['package']} for {challenge.title}.
Task: {challenge.description}
Provide a verifiable ReAct trajectory using the 5-Phase Trajectory.

CRITICAL: End your response with a final JSON answer in this format:
Answer: {{ "command": "...", "expected_output": "..." }}
"""
        # The Good Response (Chosen)
        chosen = f"{instance.trajectory}\n\nAnswer: {instance.final_output}"

        # The Bad Response (Rejected)
        rejected = self.create_rejected_instance(challenge, instance.variables)

        return {
            "prompt": f"SYSTEM: You are an Android Security Expert agent. You observe before acting. You verify every claim.\n\n{prompt}",
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {"challenge": challenge.id}
        }

    def generate_dataset(self, num_variations: int = 50) -> Path:
        all_examples = []
        print(f"Generating {num_variations} DPO pairs...")
        for challenge in CHALLENGES:
            for _ in range(num_variations):
                instance = self.create_instance(challenge)
                # Switch to DPO formatting
                example = self.format_for_dpo(instance, challenge)
                all_examples.append(example)
        random.shuffle(all_examples)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"yellow_belt_dpo_{timestamp}.jsonl"
        filepath = self.output_dir / filename
        with open(filepath, "w") as f:
            for ex in all_examples:
                f.write(json.dumps(ex) + "\n")
        print(f"Saved {len(all_examples)} DPO pairs to {filepath}")
        return filepath

if __name__ == "__main__":
    output_dir = Path(__file__).parent.parent / "training_data"
    generator = ReActGenerator(output_dir)
    generator.generate_dataset(num_variations=100) # 1100 examples total (11 challenges)
