"""Executor with training safety blocklist."""

from __future__ import annotations
import logging, os, re, subprocess, time
from dataclasses import dataclass
from typing import Optional
from dojo.exceptions import ExecutionError
from dojo.models import Challenge, ScriptType

logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    error_type: Optional[str] = None
    blocked: bool = False
    def to_dict(self): return {"success":self.success,"exit_code":self.exit_code,"stdout":self.stdout,"stderr":self.stderr,"duration":self.duration,"command":self.command,"error_type":self.error_type,"blocked":self.blocked}

class Executor:
    DANGEROUS_COMMAND_PATTERNS = {
        "destructive_delete": [r"\brm\s+-rf\b", r"\brm\s+.*\s+/sdcard"],
        "destructive_format": [r"\bmkfs\.", r"\bdd\s+of=/dev/"],
        "bootloader_flash": [r"\bfastboot\s+flash\b", r"\bfastboot\s+erase\b"],
        "system_control": [r"\breboot\s+bootloader\b", r"\bshutdown\b"],
        "adb_dangerous": [r"\bsideload\b", r"\bdisable-verity\b"],
    }
    ERROR_PATTERNS = {
        "device_offline": [r"error: device .* not found", r"no devices/emulators found"],
        "permission_denied": [r"Permission denied", r"access denied"],
        "timeout": [r"timed out", r"timeout"],
    }
    def __init__(self, device_id=None, adb_path=None, timeout=30, allow_real_device=None, disable_blocklist=False):
        self.device_id = device_id or os.getenv("EMULATOR_DEVICE", "emulator-5554")
        self.adb_path = adb_path or os.getenv("ADB_PATH", "adb")
        self.timeout, self.disable_blocklist = timeout, disable_blocklist
        if allow_real_device is None: allow_real_device = os.getenv("ALLOW_REAL_DEVICE", "").lower() == "true"
        if not allow_real_device and not self._is_emulator_device(self.device_id):
            raise ValueError(f"Device {self.device_id} not emulator. Set ALLOW_REAL_DEVICE=true")
        logger.info(f"Executor: {self.device_id}, blocklist={not disable_blocklist}")
    def _is_emulator_device(self, d): return any(re.match(p, d) for p in [r"^emulator-\d+$", r"^localhost:\d+$", r"^127\.0\.0\.1:\d+$"])
    def _check_dangerous_command(self, cmd):
        if self.disable_blocklist: return None
        for cat, pats in self.DANGEROUS_COMMAND_PATTERNS.items():
            for p in pats:
                if re.search(p, cmd, re.I): return (cat, p)
    def _classify_error(self, err, out):
        for t, ps in self.ERROR_PATTERNS.items():
            for p in ps:
                if re.search(p, f"{err}\n{out}", re.I): return t
    def _build_adb_command(self, cmd):
        cmd = cmd.strip()
        if cmd.lower().startswith("adb "): cmd = cmd[4:].strip()
        parts = [self.adb_path, "-s", self.device_id]
        if cmd.startswith("shell "): parts += ["shell", cmd[6:].strip()]
        else: parts += cmd.split()
        return parts
    def execute_adb(self, command, timeout=None):
        timeout = timeout or self.timeout
        t0 = time.time()
        dang = self._check_dangerous_command(command)
        if dang:
            logger.warning(f"BLOCKED {dang[0]}: {command[:80]}")
            return ExecutionResult(False, -2, "", f"BLOCKED: {dang[0]}", time.time()-t0, command, "blocked_dangerous", True)
        parts = self._build_adb_command(command)
        try:
            r = subprocess.run(parts, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
            et = self._classify_error(r.stderr, r.stdout)
            return ExecutionResult(r.returncode==0 and et is None, r.returncode, r.stdout.strip(), r.stderr.strip(), time.time()-t0, " ".join(parts), et, False)
        except subprocess.TimeoutExpired: return ExecutionResult(False, -1, "", f"Timeout {timeout}s", time.time()-t0, " ".join(parts), "timeout", False)
        except Exception as e: return ExecutionResult(False, -1, "", str(e), time.time()-t0, " ".join(parts), "unknown", False)
    def execute(self, challenge, model_output):
        if challenge.expected_output.script_type == ScriptType.ADB: return self.execute_adb(model_output)
        raise ExecutionError(f"Unsupported", script_type=challenge.expected_output.script_type.value)
    def check_device_connected(self):
        r = self.execute_adb("shell echo ping")
        return r.success and "ping" in r.stdout
    def get_device_info(self):
        i = {}
        for p, k in [("ro.build.version.release","android_version"),("ro.build.version.sdk","api_level"),("ro.product.model","model")]:
            r = self.execute_adb(f"shell getprop {p}")
            if r.success: i[k] = r.stdout.strip()
        return i
    def validate_output(self, c, r):
        if not r.success: return False
        v = c.inputs.additional_context.get("validation", {})
        if not v: return True
        t, o = v.get("type",""), r.stdout
        if t=="output_contains": return v.get("expected","") in o
        if t=="regex_match": return bool(re.search(v.get("pattern",""), o))
        return True