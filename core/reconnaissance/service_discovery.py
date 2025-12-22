"""
Service Discovery

Discovers running services, open ports, and network exposure on Android devices.
Identifies potential attack vectors through network and IPC enumeration.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .device_enum import ADBConnection

logger = logging.getLogger(__name__)


class ServiceType(Enum):
    NETWORK = "network"           # TCP/UDP services
    ANDROID_SERVICE = "android"   # Android system services
    APP_SERVICE = "app"           # Application services
    BROADCAST_RECEIVER = "broadcast"
    CONTENT_PROVIDER = "provider"
    ACTIVITY = "activity"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NetworkService:
    """Discovered network service."""
    protocol: str  # tcp/udp
    port: int
    state: str     # LISTEN, ESTABLISHED, etc.
    process: Optional[str]
    pid: Optional[int]
    risk: RiskLevel
    description: str


@dataclass
class AndroidService:
    """Discovered Android service."""
    name: str
    package: str
    is_running: bool
    is_exported: bool
    requires_permission: Optional[str]
    risk: RiskLevel


@dataclass
class ExposedComponent:
    """Exposed Android component (activity, receiver, provider)."""
    component_type: ServiceType
    name: str
    package: str
    is_exported: bool
    intent_filters: list[str]
    permissions: list[str]
    risk: RiskLevel


@dataclass
class ServiceDiscoveryResult:
    """Complete service discovery results."""
    network_services: list[NetworkService]
    android_services: list[AndroidService]
    exposed_components: list[ExposedComponent]
    total_attack_surface: int

    @property
    def critical_exposures(self) -> int:
        return sum(1 for s in self.network_services if s.risk == RiskLevel.CRITICAL) + \
               sum(1 for c in self.exposed_components if c.risk == RiskLevel.CRITICAL)


# Known risky ports and their descriptions
KNOWN_PORTS = {
    21: ("FTP", RiskLevel.HIGH, "File Transfer Protocol"),
    22: ("SSH", RiskLevel.MEDIUM, "Secure Shell"),
    23: ("Telnet", RiskLevel.CRITICAL, "Unencrypted remote access"),
    80: ("HTTP", RiskLevel.MEDIUM, "Web server"),
    443: ("HTTPS", RiskLevel.LOW, "Secure web server"),
    3389: ("RDP", RiskLevel.HIGH, "Remote Desktop"),
    5555: ("ADB", RiskLevel.CRITICAL, "Android Debug Bridge"),
    5037: ("ADB Server", RiskLevel.HIGH, "ADB daemon"),
    8080: ("HTTP Proxy", RiskLevel.MEDIUM, "Web proxy/debug server"),
    8443: ("HTTPS Alt", RiskLevel.LOW, "Alternative HTTPS"),
    27042: ("Frida", RiskLevel.CRITICAL, "Frida instrumentation server"),
    27043: ("Frida", RiskLevel.CRITICAL, "Frida instrumentation server"),
    4444: ("Metasploit", RiskLevel.CRITICAL, "Common reverse shell port"),
    1337: ("Elite", RiskLevel.HIGH, "Common backdoor port"),
}


class ServiceDiscovery:
    """
    Comprehensive service discovery for Android devices.

    Discovers:
    - Network services (open ports, listening sockets)
    - Android system services
    - Exported app components (activities, services, receivers, providers)
    - IPC attack surface
    """

    def __init__(self, adb: ADBConnection):
        self.adb = adb

    def discover_all(self) -> ServiceDiscoveryResult:
        """Run complete service discovery."""
        logger.info("Starting comprehensive service discovery...")

        network_services = self.discover_network_services()
        android_services = self.discover_android_services()
        exposed_components = self.discover_exposed_components()

        total = len(network_services) + len(android_services) + len(exposed_components)

        return ServiceDiscoveryResult(
            network_services=network_services,
            android_services=android_services,
            exposed_components=exposed_components,
            total_attack_surface=total,
        )

    def discover_network_services(self) -> list[NetworkService]:
        """Discover network services via netstat/ss."""
        logger.info("Discovering network services...")
        services = []

        # Try netstat first, fall back to ss
        output = self.adb.shell("netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null")

        for line in output.split('\n'):
            if 'LISTEN' not in line and 'tcp' not in line.lower():
                continue

            service = self._parse_netstat_line(line)
            if service:
                services.append(service)

        # Also check UDP
        udp_output = self.adb.shell("netstat -ulnp 2>/dev/null || ss -ulnp 2>/dev/null")
        for line in udp_output.split('\n'):
            if 'udp' in line.lower():
                service = self._parse_netstat_line(line, protocol='udp')
                if service:
                    services.append(service)

        logger.info(f"Found {len(services)} network services")
        return services

    def _parse_netstat_line(self, line: str, protocol: str = 'tcp') -> Optional[NetworkService]:
        """Parse a netstat/ss output line."""
        # Pattern for netstat: tcp 0 0 0.0.0.0:5555 0.0.0.0:* LISTEN 1234/adbd
        # Pattern for ss: LISTEN 0 128 *:5555 *:* users:(("adbd",pid=1234,fd=3))

        port_match = re.search(r':(\d+)\s', line)
        if not port_match:
            return None

        port = int(port_match.group(1))

        # Skip low-privilege high ports unless known
        if port > 10000 and port not in KNOWN_PORTS:
            return None

        # Extract process info
        process = None
        pid = None
        pid_match = re.search(r'(\d+)/(\S+)', line)
        if pid_match:
            pid = int(pid_match.group(1))
            process = pid_match.group(2)

        # Get risk level and description
        if port in KNOWN_PORTS:
            name, risk, description = KNOWN_PORTS[port]
        else:
            name = f"Port {port}"
            risk = RiskLevel.INFO
            description = "Unknown service"

        return NetworkService(
            protocol=protocol,
            port=port,
            state="LISTEN",
            process=process,
            pid=pid,
            risk=risk,
            description=f"{name}: {description}",
        )

    def discover_android_services(self) -> list[AndroidService]:
        """Discover running Android services."""
        logger.info("Discovering Android services...")
        services = []

        # Get running services
        output = self.adb.shell("dumpsys activity services | grep -E '(ServiceRecord|intent=)'")

        for line in output.split('\n'):
            if 'ServiceRecord' in line:
                # Extract service info
                match = re.search(r'ServiceRecord\{[^}]+ ([^/]+)/([^}]+)\}', line)
                if match:
                    package = match.group(1)
                    name = match.group(2)

                    # Check if exported
                    is_exported = self._check_service_exported(package, name)

                    services.append(AndroidService(
                        name=name,
                        package=package,
                        is_running=True,
                        is_exported=is_exported,
                        requires_permission=None,
                        risk=RiskLevel.MEDIUM if is_exported else RiskLevel.LOW,
                    ))

        logger.info(f"Found {len(services)} running Android services")
        return services

    def _check_service_exported(self, package: str, service: str) -> bool:
        """Check if a service is exported."""
        output = self.adb.shell(f"dumpsys package {package} | grep -A5 '{service}'")
        return 'exported=true' in output.lower()

    def discover_exposed_components(self) -> list[ExposedComponent]:
        """Discover exported app components."""
        logger.info("Discovering exposed components...")
        components = []

        # Get third-party packages
        packages = self.adb.shell("pm list packages -3 | cut -d: -f2")

        for pkg in packages.split('\n')[:30]:  # Limit for performance
            pkg = pkg.strip()
            if not pkg:
                continue

            pkg_components = self._analyze_package_components(pkg)
            components.extend(pkg_components)

        logger.info(f"Found {len(components)} exposed components")
        return components

    def _analyze_package_components(self, package: str) -> list[ExposedComponent]:
        """Analyze a package for exported components."""
        components = []

        output = self.adb.shell(f"dumpsys package {package}")

        # Parse activities
        activity_section = re.search(r'Activity Resolver Table:.*?(?=\n\n|\Z)', output, re.DOTALL)
        if activity_section:
            for match in re.finditer(r'(\S+)/(\S+) filter', activity_section.group()):
                components.append(ExposedComponent(
                    component_type=ServiceType.ACTIVITY,
                    name=match.group(2),
                    package=match.group(1),
                    is_exported=True,
                    intent_filters=[],
                    permissions=[],
                    risk=RiskLevel.MEDIUM,
                ))

        # Parse receivers
        if 'Receiver Resolver Table:' in output:
            receiver_section = re.search(r'Receiver Resolver Table:.*?(?=\n\n|\Z)', output, re.DOTALL)
            if receiver_section:
                for match in re.finditer(r'(\S+)/(\S+) filter', receiver_section.group()):
                    components.append(ExposedComponent(
                        component_type=ServiceType.BROADCAST_RECEIVER,
                        name=match.group(2),
                        package=match.group(1),
                        is_exported=True,
                        intent_filters=[],
                        permissions=[],
                        risk=RiskLevel.MEDIUM,
                    ))

        # Parse providers
        if 'ContentProvider' in output:
            for match in re.finditer(r'Provider \[([^\]]+)\].*?authority=([^\s;]+)', output):
                components.append(ExposedComponent(
                    component_type=ServiceType.CONTENT_PROVIDER,
                    name=match.group(1),
                    package=package,
                    is_exported=True,
                    intent_filters=[],
                    permissions=[],
                    risk=RiskLevel.HIGH,  # Providers often contain sensitive data
                ))

        return components

    def find_adb_exposure(self) -> Optional[NetworkService]:
        """Specifically check for ADB network exposure."""
        services = self.discover_network_services()
        for service in services:
            if service.port == 5555:
                return service
        return None

    def find_debug_services(self) -> list[NetworkService]:
        """Find common debug/development services."""
        debug_ports = [5555, 8080, 8443, 27042, 27043, 4444]
        services = self.discover_network_services()
        return [s for s in services if s.port in debug_ports]

    def generate_report(self, result: ServiceDiscoveryResult) -> str:
        """Generate service discovery report."""
        lines = [
            "=" * 70,
            "SERVICE DISCOVERY REPORT",
            "=" * 70,
            f"Total Attack Surface: {result.total_attack_surface} components",
            f"Critical Exposures: {result.critical_exposures}",
            "",
        ]

        # Network Services
        lines.append("NETWORK SERVICES")
        lines.append("-" * 70)
        if result.network_services:
            for svc in sorted(result.network_services, key=lambda s: s.port):
                risk_icon = "🔴" if svc.risk == RiskLevel.CRITICAL else \
                           "🟠" if svc.risk == RiskLevel.HIGH else \
                           "🟡" if svc.risk == RiskLevel.MEDIUM else "🟢"
                lines.append(f"  {risk_icon} {svc.protocol.upper()}:{svc.port} - {svc.description}")
                if svc.process:
                    lines.append(f"      Process: {svc.process} (PID: {svc.pid})")
        else:
            lines.append("  No exposed network services found")

        lines.append("")

        # Android Services
        lines.append("ANDROID SERVICES (Running & Exported)")
        lines.append("-" * 70)
        exported_services = [s for s in result.android_services if s.is_exported]
        if exported_services:
            for svc in exported_services[:20]:
                lines.append(f"  [{svc.risk.value.upper()}] {svc.package}/{svc.name}")
        else:
            lines.append("  No exported services found")

        lines.append("")

        # Exposed Components
        lines.append("EXPOSED APP COMPONENTS")
        lines.append("-" * 70)
        if result.exposed_components:
            by_type = {}
            for comp in result.exposed_components:
                t = comp.component_type.value
                if t not in by_type:
                    by_type[t] = []
                by_type[t].append(comp)

            for comp_type, comps in by_type.items():
                lines.append(f"  {comp_type.upper()}: {len(comps)} exposed")
                for comp in comps[:5]:
                    lines.append(f"    - {comp.package}/{comp.name}")
                if len(comps) > 5:
                    lines.append(f"    ... and {len(comps) - 5} more")
        else:
            lines.append("  No exposed components found")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)
