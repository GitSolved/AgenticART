"""
1-Day Vulnerability Demonstrator

Provides end-to-end demonstration of known (1-day) vulnerabilities:
1. Match CVEs to target device
2. Retrieve exploit templates and PoC code
3. Use LLM to adapt exploit for specific target
4. Execute and verify exploitation
5. Generate demonstration report

For authorized security testing only.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .templates import (
    ExploitTemplate,
    VulnerabilityClass,
    get_template,
    CVE_TO_TEMPLATE,
    EXPLOIT_TEMPLATES,
)
from .poc_fetcher import PoCFetcher, PoCEntry, get_poc_code

logger = logging.getLogger(__name__)


@dataclass
class DeviceProfile:
    """Target device profile for exploitation."""
    device_id: str  # ADB device ID
    android_version: str
    api_level: int
    security_patch: str
    kernel_version: Optional[str] = None
    chipset: Optional[str] = None  # qualcomm, mediatek, exynos
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    arch: str = "arm64"
    is_rooted: bool = False
    selinux_status: str = "enforcing"


@dataclass
class ExploitAttempt:
    """Record of an exploitation attempt."""
    cve_id: str
    template_name: Optional[str]
    adapted_code: str
    execution_output: str
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None


@dataclass
class DemonstrationReport:
    """Full report of 1-day demonstration."""
    device: DeviceProfile
    target_cve: str
    vulnerability_class: str
    template_used: Optional[str]
    poc_source: Optional[str]
    attempts: list[ExploitAttempt]
    final_success: bool
    proof_of_exploitation: Optional[str]  # Screenshot, log, etc.
    recommendations: list[str]
    timestamp: datetime = field(default_factory=datetime.now)


class OneDayDemonstrator:
    """
    Demonstrates 1-day vulnerabilities on target devices.

    Workflow:
    1. Profile target device
    2. Match applicable CVEs
    3. Select best exploit approach
    4. Adapt exploit using LLM
    5. Execute with governance checks
    6. Verify and report

    Usage:
        demonstrator = OneDayDemonstrator(device_id="192.168.56.101:5555")
        report = demonstrator.demonstrate("CVE-2022-0847")
        print(report.final_success)
    """

    def __init__(
        self,
        device_id: str,
        llm_client=None,
        max_attempts: int = 3,
        output_dir: str = "output/demonstrations",
    ):
        self.device_id = device_id
        self.max_attempts = max_attempts
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.poc_fetcher = PoCFetcher()

        # LLM client for adaptation
        if llm_client is None:
            from agent import LLMClient
            self.llm_client = LLMClient.create()
        else:
            self.llm_client = llm_client

        # Device profile (populated on first use)
        self._device_profile: Optional[DeviceProfile] = None

    @property
    def device(self) -> DeviceProfile:
        """Get or create device profile."""
        if self._device_profile is None:
            self._device_profile = self._profile_device()
        return self._device_profile

    def _profile_device(self) -> DeviceProfile:
        """Profile the target device via ADB."""
        def adb_getprop(prop: str) -> str:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "getprop", prop],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()

        def adb_shell(cmd: str) -> str:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", cmd],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()

        # Get device properties
        android_version = adb_getprop("ro.build.version.release")
        api_level = int(adb_getprop("ro.build.version.sdk") or "0")
        security_patch = adb_getprop("ro.build.version.security_patch")
        kernel = adb_shell("uname -r")
        manufacturer = adb_getprop("ro.product.manufacturer")
        model = adb_getprop("ro.product.model")

        # Detect chipset
        chipset = None
        hardware = adb_getprop("ro.hardware")
        if "qcom" in hardware.lower() or "qualcomm" in hardware.lower():
            chipset = "qualcomm"
        elif "mt" in hardware.lower() or "mediatek" in hardware.lower():
            chipset = "mediatek"
        elif "exynos" in hardware.lower():
            chipset = "exynos"

        # Check root status
        root_check = adb_shell("su -c 'id' 2>/dev/null || echo 'not_root'")
        is_rooted = "uid=0" in root_check

        # Check SELinux
        selinux = adb_shell("getenforce 2>/dev/null || echo 'unknown'")

        # Detect architecture
        arch = adb_shell("uname -m")
        if "aarch64" in arch or "arm64" in arch:
            arch = "arm64"
        elif "arm" in arch:
            arch = "arm"
        elif "x86_64" in arch:
            arch = "x86_64"

        return DeviceProfile(
            device_id=self.device_id,
            android_version=android_version,
            api_level=api_level,
            security_patch=security_patch,
            kernel_version=kernel,
            chipset=chipset,
            manufacturer=manufacturer,
            model=model,
            arch=arch,
            is_rooted=is_rooted,
            selinux_status=selinux.lower(),
        )

    def demonstrate(self, cve_id: str) -> DemonstrationReport:
        """
        Demonstrate a specific CVE on the target device.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2022-0847")

        Returns:
            DemonstrationReport with results
        """
        logger.info(f"Starting 1-day demonstration: {cve_id}")
        logger.info(f"Target: {self.device}")

        attempts = []
        final_success = False
        proof = None

        # Get template and PoC
        template = get_template(cve_id)
        poc_code = get_poc_code(cve_id)

        vuln_class = template.vuln_class.value if template else "unknown"
        template_name = template.name if template else None
        poc_source = "github" if poc_code else None

        for attempt_num in range(1, self.max_attempts + 1):
            logger.info(f"Attempt {attempt_num}/{self.max_attempts}")

            try:
                # Adapt exploit for target
                adapted_code = self._adapt_exploit(
                    cve_id=cve_id,
                    template=template,
                    poc_code=poc_code,
                    previous_attempts=attempts,
                )

                # Execute exploit
                output, success = self._execute_exploit(adapted_code)

                attempt = ExploitAttempt(
                    cve_id=cve_id,
                    template_name=template_name,
                    adapted_code=adapted_code,
                    execution_output=output,
                    success=success,
                )
                attempts.append(attempt)

                if success:
                    final_success = True
                    proof = self._gather_proof()
                    logger.info(f"[+] Exploitation successful on attempt {attempt_num}!")
                    break
                else:
                    logger.warning(f"Attempt {attempt_num} failed, will retry with feedback")

            except Exception as e:
                logger.error(f"Attempt {attempt_num} error: {e}")
                attempts.append(ExploitAttempt(
                    cve_id=cve_id,
                    template_name=template_name,
                    adapted_code="",
                    execution_output="",
                    success=False,
                    error=str(e),
                ))

        # Generate report
        report = DemonstrationReport(
            device=self.device,
            target_cve=cve_id,
            vulnerability_class=vuln_class,
            template_used=template_name,
            poc_source=poc_source,
            attempts=attempts,
            final_success=final_success,
            proof_of_exploitation=proof,
            recommendations=self._generate_recommendations(cve_id, final_success),
        )

        # Save report
        self._save_report(report)

        return report

    def _adapt_exploit(
        self,
        cve_id: str,
        template: Optional[ExploitTemplate],
        poc_code: Optional[str],
        previous_attempts: list[ExploitAttempt],
    ) -> str:
        """Use LLM to adapt exploit for target device."""

        # Build context
        device_context = f"""
Target Device Profile:
- Device ID: {self.device.device_id}
- Android Version: {self.device.android_version}
- API Level: {self.device.api_level}
- Security Patch: {self.device.security_patch}
- Kernel: {self.device.kernel_version}
- Architecture: {self.device.arch}
- Chipset: {self.device.chipset}
- Manufacturer: {self.device.manufacturer}
- Model: {self.device.model}
- Rooted: {self.device.is_rooted}
- SELinux: {self.device.selinux_status}
"""

        # Build prompt
        prompt_parts = [
            f"Generate a working exploit script for {cve_id}.",
            "",
            device_context,
        ]

        if template:
            prompt_parts.extend([
                "",
                "=== EXPLOIT TEMPLATE ===",
                f"Vulnerability Class: {template.vuln_class.value}",
                f"Target Component: {template.target_component}",
                "",
                "Prerequisites:",
                *[f"- {p}" for p in template.prerequisites],
                "",
                "Exploit Steps:",
                *template.exploit_steps,
                "",
                "Template Code:",
                "```",
                template.code_template,
                "```",
                "",
                "Adaptation Hints:",
                *[f"- {h}" for h in template.adaptation_hints],
            ])

        if poc_code:
            prompt_parts.extend([
                "",
                "=== REFERENCE POC CODE ===",
                "```",
                poc_code[:5000],  # Limit length
                "```",
            ])

        if previous_attempts:
            prompt_parts.extend([
                "",
                "=== PREVIOUS FAILED ATTEMPTS ===",
            ])
            for i, attempt in enumerate(previous_attempts[-2:], 1):  # Last 2 attempts
                prompt_parts.extend([
                    f"Attempt {i}:",
                    f"Error: {attempt.error or attempt.execution_output[:500]}",
                    "",
                ])
            prompt_parts.append("Fix the issues from previous attempts.")

        prompt_parts.extend([
            "",
            "REQUIREMENTS:",
            "1. Generate a complete, executable Python script",
            "2. Adapt all hardcoded values for the target device",
            "3. Include proper error handling",
            "4. Add verification that exploit succeeded",
            "5. Use ADB commands appropriate for the target",
            "",
            "Output ONLY the Python code, no explanations.",
        ])

        prompt = "\n".join(prompt_parts)

        # Call LLM
        system_prompt = """You are an expert Android security researcher.
Generate working exploit code for authorized penetration testing.
Adapt the provided template/PoC for the specific target device.
Output clean, executable Python code only."""

        response = self.llm_client.complete(prompt, system=system_prompt)

        # Extract code from response
        code = self._extract_code(response.content)

        return code

    def _extract_code(self, response: str) -> str:
        """Extract Python code from LLM response."""
        # Try to find code blocks
        import re

        # Match ```python ... ``` or ``` ... ```
        pattern = r"```(?:python)?\n(.*?)```"
        matches = re.findall(pattern, response, re.DOTALL)

        if matches:
            return matches[0].strip()

        # If no code blocks, assume entire response is code
        if response.strip().startswith(("#!/", "import ", "from ", "def ", "class ")):
            return response.strip()

        return response

    def _execute_exploit(self, code: str) -> tuple[str, bool]:
        """Execute the exploit code and check for success."""
        # Save exploit to temp file
        exploit_path = self.output_dir / "current_exploit.py"
        exploit_path.write_text(code)

        # Execute
        try:
            result = subprocess.run(
                ["python3", str(exploit_path)],
                capture_output=True,
                text=True,
                timeout=120,
                env={**__import__("os").environ, "DEVICE_ID": self.device_id},
            )
            output = result.stdout + result.stderr

            # Check for success indicators
            success_indicators = [
                "uid=0",
                "root",
                "SUCCESS",
                "Exploit successful",
                "GOT ROOT",
                "Privilege escalation successful",
            ]

            success = any(ind.lower() in output.lower() for ind in success_indicators)

            return output, success

        except subprocess.TimeoutExpired:
            return "Execution timed out", False
        except Exception as e:
            return f"Execution error: {e}", False

    def _gather_proof(self) -> str:
        """Gather proof of successful exploitation."""
        proofs = []

        # Get current user
        result = subprocess.run(
            ["adb", "-s", self.device_id, "shell", "id"],
            capture_output=True, text=True
        )
        proofs.append(f"User ID: {result.stdout.strip()}")

        # Check SELinux
        result = subprocess.run(
            ["adb", "-s", self.device_id, "shell", "getenforce"],
            capture_output=True, text=True
        )
        proofs.append(f"SELinux: {result.stdout.strip()}")

        # Try to access protected files
        result = subprocess.run(
            ["adb", "-s", self.device_id, "shell", "ls", "-la", "/data/data"],
            capture_output=True, text=True
        )
        if "Permission denied" not in result.stderr:
            proofs.append("Can access /data/data")

        return "\n".join(proofs)

    def _generate_recommendations(self, cve_id: str, exploited: bool) -> list[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if exploited:
            recommendations.append(f"CRITICAL: Device is vulnerable to {cve_id}")
            recommendations.append(f"Update security patch level (current: {self.device.security_patch})")
            recommendations.append("Apply vendor security updates immediately")
        else:
            recommendations.append(f"Device appears not vulnerable to {cve_id}")
            recommendations.append("Continue monitoring for new vulnerabilities")

        # General recommendations
        recommendations.extend([
            "Enable automatic security updates",
            "Use device with active vendor support",
            "Consider enterprise MDM for fleet management",
        ])

        return recommendations

    def _save_report(self, report: DemonstrationReport):
        """Save demonstration report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"report_{report.target_cve}_{timestamp}.json"

        # Convert to dict (simplified)
        report_dict = {
            "cve": report.target_cve,
            "device": {
                "id": report.device.device_id,
                "android": report.device.android_version,
                "patch": report.device.security_patch,
                "kernel": report.device.kernel_version,
            },
            "vulnerability_class": report.vulnerability_class,
            "template_used": report.template_used,
            "poc_source": report.poc_source,
            "attempts": len(report.attempts),
            "success": report.final_success,
            "proof": report.proof_of_exploitation,
            "recommendations": report.recommendations,
            "timestamp": report.timestamp.isoformat(),
        }

        report_path.write_text(json.dumps(report_dict, indent=2))
        logger.info(f"Report saved: {report_path}")

    def list_applicable_cves(self) -> list[str]:
        """List CVEs that may affect this device based on its profile."""
        from core.scanning.cve_matcher import CVEMatcher

        matcher = CVEMatcher()
        matches = matcher.match_device(
            android_version=self.device.android_version,
            api_level=self.device.api_level,
            security_patch=self.device.security_patch,
        )

        # Filter to those with templates
        applicable = []
        for cve in matches:
            if cve.cve_id in CVE_TO_TEMPLATE:
                applicable.append(cve.cve_id)

        return applicable


# Quick access function
def demonstrate_cve(cve_id: str, device_id: str) -> DemonstrationReport:
    """Quick function to demonstrate a CVE."""
    demonstrator = OneDayDemonstrator(device_id=device_id)
    return demonstrator.demonstrate(cve_id)
