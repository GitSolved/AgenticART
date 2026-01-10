# Android Zero‑Day Research Curriculum Framework  
**Target Learner**: Advanced cybersecurity practitioner transitioning to Android vulnerability research  
**Delivery Model**: Local LM Teacher/Student (Socratic dialogue + hands‑on labs)  
**Terminal Objective**: Student independently discovers and weaponizes a novel zero‑day vulnerability in Android OS or pre‑installed OEM software  

***

## 1. Outcome‑Based Competency Architecture  

### Terminal Competency (Zero‑Day Ready)  
Student demonstrates ability to:  
- **Identify** a previously unknown vulnerability in Android framework, kernel, or privileged OEM app (e.g., system service, HAL, TrustZone applet)  
- **Root‑cause** the flaw via source‑aware static analysis and dynamic tracing  
- **Develop** a reliable exploit chain that bypasses modern mitigations (ASLR, CFI, SELinux, sandboxing)  
- **Weaponize** exploit into a PoC that achieves arbitrary code execution or privilege escalation  
- **Document** findings in a professional vulnerability report suitable for vendor disclosure or bug bounty  

### Milestone Competencies (Progressive Gates)  
| Milestone | Competency Description | Evidence of Mastery |
|-----------|------------------------|---------------------|
| **M1: Android Internals Fluency** | Explain Binder IPC, Zygote fork model, ART runtime, SELinux policy, and boot chain security | Whiteboard explanation + live debugging of system service call flow |
| **M2: Vulnerability Pattern Recognition** | Catalog and classify 50+ CVEs by root cause (UAF, TOCTOU, confused deputy, logic bug) | Annotated CVE database with PoC reproductions for 10 critical bugs |
| **M3: Static Analysis Operator** | Use Ghidra + custom scripts to identify dangerous code patterns in AOSP (~1M LOC) | Discover 3 known vulnerabilities in older AOSP tags without reading CVEs |
| **M4: Dynamic Analysis & Fuzzing** | Build coverage‑guided fuzzer for a HAL service and find 1 crash with security impact | Fuzzer harness + triaged crash report with ASAN/UBSAN output |
| **M5: Exploit Development** | Write working exploit for a known CVE, bypassing ASLR via infoleak and achieving code exec | Working exploit + write‑up explaining mitigation bypass technique |
| **M6: Zero‑Day Discovery** | Find and exploit novel vulnerability in latest Pixel firmware (or Samsung/OEM equivalent) | Original vulnerability report + weaponized PoC + responsible disclosure |

***

## 2. Curriculum Structure: Modules & Sequencing  

### Phase 1: Foundation & Tooling (Weeks 1‑4)  
**Goal**: Build reproducible research environment and deep OS fluency.  

| Module | Content | LM‑Teacher Role | Student Deliverable |
|--------|---------|-----------------|---------------------|
| **1.1 Android Build System & AOSP** | Repo sync, lunch combos, make targets, vendor image extraction | Guide student through building Pixel factory image from source; explain build artifacts | Custom AOSP build with debug symbols for `system_server` |
| **1.2 Dynamic Analysis Platform** | Magisk, Frida, KernelSU, Qemu+GDB, HWASan, KASAN | Socratic setup: “Why must we patch SELinux policy for Frida? What’s the trade‑off?” | Automated device farm (2× rooted Pixel devices + Qemu) with CI pipeline |
| **1.3 Static Analysis Pipeline** | Ghidra headless, Python scripting, CodeQL for Java/C++, Semgrep rules | Pair‑program Ghidra script to trace `Parcel` read/write mismatch patterns | Custom Ghidra script that flags unvalidated `readString()` calls in system services |
| **1.4 Threat Modeling Android** | Attack surface mapping (intents, content providers, HALs, TrustZone), STRIDE on AOSP | Facilitate threat model workshop: “Map entry points for a malicious app to escalate to `system`” | Comprehensive attack‑surface document for a chosen OEM device |

***

### Phase 2: Vulnerability Deep Dive & Pattern Catalog (Weeks 5‑10)  
**Goal**: Develop pattern‑matching intuition and hands‑on exploitation muscle memory.  

| Module | Content | LM‑Teacher Role | Student Deliverable |
|--------|---------|-----------------|---------------------|
| **2.1 CVE Reproduction Lab** | Select 10 high‑impact CVEs (e.g., CVE‑2020‑0041, CVE‑2021‑1046, CVE‑2022‑20413) | Debug alongside student: “Why does this UAF trigger only after `onTransact` returns?” | Git repo with reproducible PoCs, exploit primitives, and root‑cause notes for each CVE |
| **2.2 Vulnerability Taxonomy** | Classify by component (framework, kernel, driver, OEM), root cause, exploit primitive | Quiz student: “Given this crash dump, which CWE bucket? What’s the likely patch pattern?” | Curated taxonomy database (SQLite) with 50+ CVEs, searchable by component and primitive |
| **2.3 Fuzzing & Concolic Execution** | AFL++ for native services, libFuzzer for JNI, Angr for symbolic tracing of `system_server` | Code‑review fuzzer harness: “How do you model `Binder` transaction input grammar?” | Working fuzzer that finds 3+ unique crashes in a target HAL; triage report with 1 security bug |
| **2.4 Exploit Primitives Workshop** | Infoleaks (heap pointer leak, uninitialized memory), UAF exploitation, type confusion | Live pair‑exploit: “We have a 16‑byte heap overflow—build a fake `vtable` to hijack control” | Arsenal of 5+ exploit primitives (e.g., arbitrary read/write, PC control) implemented for practice targets |

***

### Phase 3: Applied Research & Zero‑Day Hunting (Weeks 11‑20)  
**Goal**: Transition from known bugs to novel discovery in live targets.  

| Module | Content | LM‑Teacher Role | Student Deliverable |
|--------|---------|-----------------|---------------------|
| **3.1 Attack Surface Auditing** | Reverse engineer OEM‑specific system apps (Samsung, Xiaomi) and vendor HALs | Guide audit methodology: “Decompile this APK—trace `Intent` handlers for missing permission checks” | 1× vulnerability report (e.g., privilege escalation via unprotected broadcast) in OEM software |
| **3.2 Kernel & Driver Fuzzing** | Syzkaller setup, custom syscall descriptions, driver‑specific fuzzing (e.g., `wlan`, `audio`) | Debug kernel panic: “Is this NULL deref exploitable? How would you stabilize the race?” | 1× kernel bug (UAF or race) with PoC crash and preliminary exploitability analysis |
| **3.3 TrustZone & Secure World** | Reverse engineer `tz_service`, QSEE exploit history, secure boot bypass patterns | Deep dive: “Analyze this `qseecom` driver—find the missing `copy_from_user` validation” | 1× secure‑world vulnerability (e.g., EL3 privilege escalation) or detailed threat analysis |
| **3.4 Zero‑Day Sprint** | 4‑week intensive: student selects target (AOSP component, OEM app, kernel driver) | Daily standup: “What’s your hypothesis? Show me the crash—how do we refine the input?” | **Final Deliverable**: Novel zero‑day vulnerability + weaponized exploit + vendor disclosure report |

***

## 3. Authentic Assessment & Evidence Collection  

### Performance Tasks (Not Exams)  
- **Portfolio**: GitHub repo containing all PoCs, scripts, write‑ups, and CVE reproductions  
- **Live Demo**: Student presents exploit chain achieving root on latest Pixel (or emulator)  
- **Disclosure Simulation**: Mock vendor communication; peer‑reviewed vulnerability report  
- **Threat Model Defense**: Student defends attack‑surface analysis against red‑team probing  

### LM‑Facilitated Assessment  
The LM acts as both **mentor** and **evaluator**:  
- **Formative**: Continuous Socratic questioning (“Why did you choose this fuzzing strategy? What’s the weakest assumption?”)  
- **Summative**: LM generates novel vulnerable code snippets; student must find and exploit within timebox  
- **Calibration**: LM compares student’s root‑cause analysis against official CVE write‑ups, highlighting gaps in reasoning  

***

## 4. Scaffolding & Cognitive Supports  

### Tooling & Environment  
- **Pre‑built Docker images**: AOSP build environment, Ghidra + scripts, Frida gadget templates  
- **Template repos**: Exploit skeletons, fuzzer harness boilerplate, report templates  
- **LM‑generated hints**: On request, LM provides “hint ladder” (vague → specific → code snippet) to prevent stuckness without giving away the bug  

### Graduated Complexity  
- **Known CVEs first**: Build confidence and pattern library  
- **Semi‑known bugs**: LM introduces subtle variants of patched CVEs; student must adapt exploit  
- **True unknowns**: Student hunts on latest firmware with minimal guidance  

### Community & Peer Learning  
- **Weekly journal club**: Analyze recent Android security research; LM facilitates discussion  
- **Capture‑the‑Flag (CTF) integration**: Student competes in Android‑focused CTFs; debrief with LM on failed attempts  
- **Mentorship simulation**: LM role‑plays as senior researcher, providing code review and architectural feedback  

***

## 5. LM‑Specific Implementation Notes  

### Teacher Persona Configuration  
Configure LM to adopt **expert Android security researcher** persona:  
- **Tone**: Direct, technical, expects precise terminology (e.g., “Use `ioctl` number, not ‘magic number’”)  
- **Socratic style**: Prefers questions over answers: “What invariant is violated here? How would you verify?”  
- **Code‑first**: Answers include runnable Python/Frida/Ghidra scripts; student is expected to execute and modify  

### Dialogue Flow  
1. **Objective setting**: LM and student co‑define weekly sprint goal (e.g., “Fuzz `MediaCodec` service to find UAF”)  
2. **Exploration**: Student shares findings (crash dump, Ghidra screenshot); LM asks probing questions  
3. **Synthesis**: LM helps connect observation to vulnerability pattern (e.g., “This looks like a missing `release()` in error path—check `finally` blocks”)  
4. **Exploitation**: LM reviews exploit draft, suggests refinement (e.g., “Your infoleak is unreliable—use `timerfd` for heap grooming”)  
5. **Reflection**: LM prompts student to write root‑cause analysis and compare against official patch  

### Safety & Ethics Guardrails  
- **Policy layer**: LM must refuse to generate weaponized exploits for live, unpatched devices; only PoC for research environment  
- **Disclosure training**: LM drills responsible disclosure timeline, vendor communication etiquette, and legal boundaries (CFAA, DMCA §1201)  
- **Synthetic targets**: For high‑risk modules (e.g., TrustZone), LM provides vulnerable emulator images rather than real firmware  

***

## 6. Continuous Iteration & Maintenance  

### Curriculum as Living System  
- **Quarterly AOSP sync**: Update modules to latest Android version; integrate new mitigations (e.g., Memory Tagging, CFI improvements)  
- **CVE feed integration**: Auto‑populate reproduction lab with latest high‑impact CVEs  
- **Student feedback loop**: Student’s struggles (e.g., “Fuzzing `audioflinger` is too hard”) trigger curriculum refinement—add scaffolding or reorder modules  

### Evidence‑Based Refinement  
Track metrics:  
- **Time‑to‑first‑crash** in fuzzing modules (indicates tooling fluency)  
- **CVE reproduction success rate** (indicates pattern recognition)  
- **Zero‑day discovery rate** (ultimate outcome)  

Use data to prune ineffective modules and double down on high‑yield activities.  

***

## 7. Sample 4‑Week Zero‑Day Sprint (Detailed)  

| Week | Day | LM‑Student Interaction | Student Artifact |
|------|-----|------------------------|------------------|
| **1** | Mon | LM: “Choose a target system service. Justify why its attack surface is promising.” | Target selection memo + attack‑surface map |
| | Wed | LM: “Decompile the service; identify 5 `Parcel` read sites. Which lack validation?” | Annotated Ghidra database |
| | Fri | LM: “Build a fuzzer harness that mutates `Parcel` data. What’s your coverage metric?” | Fuzzer + initial corpus |
| **2** | Mon | LM: “You found a crash—triage: is it a UAF? Show me the heap trace.” | Triage report + ASAN output |
| | Wed | LM: “Reproduce the bug reliably. What’s the smallest input that triggers it?” | Minimized PoC |
| | Fri | LM: “How do you turn this into arbitrary read? Sketch the exploit primitive.” | Exploit primitive design doc |
| **3** | Mon | LM: “Implement the infoleak. What’s your heap grooming strategy?” | Working infoleak exploit |
| | Wed | LM: “Chain the primitives—achieve PC control. Where do you redirect execution?” | Full exploit achieving code exec |
| | Fri | LM: “Make it reliable across reboots. What assumptions remain fragile?” | Hardened exploit + reliability analysis |
| **4** | Mon | LM: “Write the vulnerability report. How do you describe impact without exaggeration?” | Draft disclosure report |
| | Wed | LM: “Peer‑review: I’ll role‑play as Google security. Defend your severity rating.” | Revised report + CVSS justification |
| | Fri | LM: “Submit to Android Security Center. What’s your follow‑up timeline?” | Submitted report + tracking ticket |

***

## Summary: Curriculum Success Checklist  

✅ **Outcome‑first**: Competencies map directly to zero‑day discovery pipeline  
✅ **Authentic work**: Every module uses real AOSP, real devices, real CVEs  
✅ **Aligned system**: Tools, instruction, and assessment all serve the same competencies  
✅ **Praxis integration**: Reasoning (pattern recognition, root‑cause analysis) taught *through* application (exploitation, fuzzing)  
✅ **Scaffolded progression**: Known → semi‑known → unknown; heavy tooling support early  
✅ **LM‑native pedagogy**: Socratic dialogue, code‑first answers, calibrated hints  
✅ **Performance assessment**: Portfolio + live exploit demo + disclosure report  
✅ **Living curriculum**: Quarterly updates, metrics‑driven refinement  

This framework transforms the abstract goal of “finding a zero‑day” into a **competency‑based, evidence‑driven, LM‑facilitated apprenticeship** where the student’s daily work is indistinguishable from professional Android security research.
