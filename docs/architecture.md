# AgenticART Architecture

## System Overview

```
+------------------------------------------------------------------------------------+
|                                                                                    |
|                            AGENTICART FRAMEWORK                                    |
|              LLM-Powered Android Exploitation + Training Data Generation           |
|                                                                                    |
+------------------------------------------------------------------------------------+
|                                                                                    |
|  +----------------+     +-------------------------------------------------------+  |
|  |                |     |                     AGENT LAYER                       |  |
|  |    USER        |     |                  (The "Engine")                       |  |
|  |                |     |                                                       |  |
|  |  +----------+  |     |  +--------------------------------------------------+ |  |
|  |  | Web UI   |--+---->|  |              ORCHESTRATION CHAIN                 | |  |
|  |  | Chat     |  |     |  |                                                  | |  |
|  |  | Scripts  |  |     |  |   +---------+  +----------------+  +-----------+ | |  |
|  |  | Chain    |  |     |  |   |         |  |    SCRIPT      |  |           | | |  |
|  |  +----------+  |     |  |   | PLANNER |->|   GENERATOR    |->|SUMMARIZER | | |  |
|  |                |     |  |   |         |  |                |  |           | | |  |
|  |  +----------+  |     |  |   +----+----+  +-------+--------+  +-----+-----+ | |  |
|  |  |   CLI    |--+---->|  |        |              |                  |       | |  |
|  |  |  Tools   |  |     |  |        v              v                  v       | |  |
|  |  +----------+  |     |  |   +----------------------------------------------+ | |  |
|  |                |     |  |   |           PROMPT TEMPLATES                   | | |  |
|  +----------------+     |  |   |  recon.md | exploit.md | scan.md | verify.md | | |  |
|                         |  |   |  adb_abuse.md | escalate.md | persistence.md | | |  |
|                         |  |   +----------------------------------------------+ | |  |
|                         |  +--------------------------------------------------+ |  |
|                         |                          |                            |  |
|                         |                          v                            |  |
|                         |  +--------------------------------------------------+ |  |
|                         |  |                 LLM PROVIDERS                     | |  |
|                         |  |                                                   | |  |
|                         |  |   +-----------+   +---------+   +-------------+   | |  |
|                         |  |   |  OLLAMA   |   | OPENAI  |   |  ANTHROPIC  |   | |  |
|                         |  |   | (Default) |   |  (API)  |   |    (API)    |   | |  |
|                         |  |   +-----------+   +---------+   +-------------+   | |  |
|                         |  +--------------------------------------------------+ |  |
|                         +-------------------------------------------------------+  |
|                                                    |                               |
|                                                    v                               |
|  +------------------------------------------------------------------------------+  |
|  |                              CORE MODULES                                    |  |
|  |                                                                              |  |
|  |  +------------------+  +------------------+  +----------------------------+  |  |
|  |  |  RECONNAISSANCE  |  |     SCANNING     |  |        EXPLOITATION        |  |  |
|  |  |                  |  |                  |  |                            |  |  |
|  |  | * ADB Connection |  | * Vuln Scanner   |  | * Exploit Runner           |  |  |
|  |  | * Device Enum    |  | * CVE Matcher    |  | * Magisk Root              |  |  |
|  |  | * Service Disc.  |  | * Perm Analyzer  |  | * Kernel Exploits          |  |  |
|  |  |                  |  |                  |  | * ADB Exploits             |  |  |
|  |  |                  |  |                  |  | * Bootloader Unlock        |  |  |
|  |  +--------+---------+  +--------+---------+  +--------------+-------------+  |  |
|  |           |                     |                           |                |  |
|  |           +---------------------+---------------------------+                |  |
|  |                                 v                                            |  |
|  |  +------------------+  +------------------+  +----------------------------+  |  |
|  |  |   VERIFICATION   |  |    GOVERNANCE    |  |     ADDITIONAL MODULES     |  |  |
|  |  |                  |  |                  |  |                            |  |  |
|  |  | * Root Check     |  | * Safety Tiers   |  | * exploits/ (attack chains)|  |  |
|  |  | * Capability Test|  | * Approval Gates |  | * cve_demo/ (demonstrations|  |  |
|  |  |                  |  | * Blocklists     |  | * traffic/ (MITM control)  |  |  |
|  |  +------------------+  +------------------+  +----------------------------+  |  |
|  +------------------------------------------------------------------------------+  |
|                                                    |                               |
|                                                    v                               |
|  +------------------------------------------------------------------------------+  |
|  |                              TARGET DEVICE                                   |  |
|  |                                                                              |  |
|  |     +--------------------------------------------------------------------+   |  |
|  |     |                      GENYMOTION EMULATOR                           |   |  |
|  |     |                                                                    |   |  |
|  |     |    +--------------+          ADB (TCP/5555)          +----------+  |   |  |
|  |     |    |   Android    |<------------------------------->|   Host   |  |   |  |
|  |     |    |   11-14      |                                 |  Machine |  |   |  |
|  |     |    |   Emulator   |       Commands / Responses      |          |  |   |  |
|  |     |    +--------------+                                 +----------+  |   |  |
|  |     |                                                                    |   |  |
|  |     +--------------------------------------------------------------------+   |  |
|  +------------------------------------------------------------------------------+  |
|                                                                                    |
+------------------------------------------------------------------------------------+
```

## Dojo Training Framework

The Dojo is the training data generation system - a key differentiator of AgenticART.

```
+------------------------------------------------------------------------------+
|                              DOJO FRAMEWORK                                  |
|                    (Training Data Generation Pipeline)                       |
+------------------------------------------------------------------------------+
|                                                                              |
|  +------------------------+    +------------------------+    +------------+  |
|  |      CURRICULUM        |    |       SPARRING         |    |   GRADING  |  |
|  |   (Challenge System)   |--->|   (Execution Layer)    |--->|  (Sensei)  |  |
|  +------------------------+    +------------------------+    +------------+  |
|  | * challenger.py        |    | * executor.py          |    | * grader.py|  |
|  | * loader.py            |    | * context_injector.py  |    | * sensei.py|  |
|  | * Belt progression     |    | * error_extractor.py   |    | * exporter |  |
|  +------------------------+    +------------------------+    +-----+------+  |
|                                                                     |        |
|                                                                     v        |
|  +-------------------------------------------------------------------+       |
|  |                    TRAINING DATA PIPELINE                         |       |
|  |                                                                   |       |
|  |  +---------------+  +---------------+  +---------------+          |       |
|  |  |   Positive    |  |   Negative    |  |    Error      |          |       |
|  |  |   Examples    |  |   Examples    |  |   Recovery    |          |       |
|  |  | (successful)  |  |  (failures)   |  |    Pairs      |          |       |
|  |  +---------------+  +---------------+  +---------------+          |       |
|  +-------------------------------------------------------------------+       |
|                                      |                                       |
|                                      v                                       |
|  +-------------------------------------------------------------------+       |
|  |                       FINE-TUNING                                 |       |
|  |                                                                   |       |
|  |  +------------------+     +------------------+                    |       |
|  |  |    packager.py   |---->|   Training Job   |                    |       |
|  |  |  (JSONL export)  |     |   (LoRA / MLX)   |                    |       |
|  |  +------------------+     +------------------+                    |       |
|  +-------------------------------------------------------------------+       |
|                                                                              |
+------------------------------------------------------------------------------+

Belt Progression:
  White -> Yellow -> Orange -> Green -> Blue -> Purple -> Brown -> Black
  (ADB)   (Recon)   (Vuln)   (Script) (CVE)  (Evasion) (Chain) (Novel)
```

## Attack Chain Flow

```
                                    START
                                      |
                                      v
                        +-----------------------------+
                        |      1. RECONNAISSANCE      |
                        |                             |
                        |  * Connect via ADB          |
                        |  * Enumerate device props   |
                        |  * Discover services        |
                        |  * Fingerprint security     |
                        +-------------+---------------+
                                      |
                                      v
                        +-----------------------------+
                        |       2. SCANNING           |
                        |                             |
                        |  * Match CVEs to device     |
                        |  * Analyze permissions      |
                        |  * Check misconfigs         |
                        |  * Score risk levels        |
                        +-------------+---------------+
                                      |
                                      v
                        +-----------------------------+
                        |     3. EXPLOITATION         |
                        |                             |
                        |  +------------------------+ |
                        |  |   LLM Script Gen       | |
                        |  |                        | |
                        |  |  "Root this device"    | |
                        |  |         |              | |
                        |  |         v              | |
                        |  |  +---------------+     | |
                        |  |  | Python/Bash   |     | |
                        |  |  |   Script      |     | |
                        |  |  +---------------+     | |
                        |  +------------------------+ |
                        |                             |
                        |  * Execute exploit          |
                        |  * Capture output           |
                        +-------------+---------------+
                                      |
                             +--------+--------+
                             |                 |
                             v                 v
                       +-----------+     +-----------+
                       |  SUCCESS  |     |  FAILURE  |
                       +-----+-----+     +-----+-----+
                             |                 |
                             |                 v
                             |    +---------------------+
                             |    |  SUMMARIZER         |
                             |    |                     |
                             |    |  * Analyze output   |
                             |    |  * Extract learnings|
                             |    |  * Suggest next     |
                             |    +----------+----------+
                             |               |
                             |               v
                             |    +---------------------+
                             |    |  PLANNER            |
                             |    |                     |
                             |    |  * Adjust strategy  |
                             |    |  * Try alternate    |
                             |    +----------+----------+
                             |               |
                             |               +------+
                             |                      |
                             v                      |
                       +-------------------------+  |
                       |     4. VERIFICATION     |  |
                       |                         |<-+
                       |  * Check root access    |   (retry loop)
                       |  * Test capabilities    |
                       +-------------+-----------+
                                     |
                                     v
                                   DONE
```

## Module Dependencies

```
                    +------------------------------------------+
                    |              webapp/app.py               |
                    |            (User Interface)              |
                    +--------------------+---------------------+
                                         |
          +------------------------------+------------------------------+
          |                              |                              |
          v                              v                              v
+-----------------------+    +-----------------------+    +-------------------+
|        agent/         |    |         core/         |    |      config/      |
|                       |    |                       |    |                   |
| +-------------------+ |    | +-------------------+ |    | * settings.yaml   |
| |    llm_client     | |    | | reconnaissance/   | |    | * .env            |
| +--------+----------+ |    | | * device_enum     | |    | * emulator/       |
|          |            |    | | * service_discov  | |    +-------------------+
| +--------v----------+ |    | +-------------------+ |
| |      planner      | |    |          |            |    +-------------------+
| +--------+----------+ |    | +--------v----------+ |    |       dojo/       |
|          |            |    | |     scanning/     | |    |                   |
| +--------v----------+ |    | | * cve_matcher     | |    | +---------------+ |
| | script_generator  |-+-+--| | * vuln_scanner    | |    | |  curriculum/  | |
| +--------+----------+ | |  | | * perm_analyzer   | |    | | * challenger  | |
|          |            | |  | +-------------------+ |    | | * executor    | |
| +--------v----------+ | |  |          |            |    | | * loader      | |
| |    summarizer     | | |  | +--------v----------+ |    | +---------------+ |
| +--------+----------+ | |  | |  exploitation/    | |    |        |          |
|          |            | |  | | * exploit_runner  | |    | +------v--------+ |
| +--------v----------+ | |  | | * techniques/     | |    | |    sensei/    | |
| |      chains/      | | |  | |   - magisk_root   | |    | | * grader      | |
| | * android_root    | | |  | |   - kernel_expl   | |    | | * exporter    | |
| +-------------------+ | |  | |   - adb_exploits  | |    | +---------------+ |
|                       | |  | |   - bootloader    | |    |        |          |
| +-------------------+ | |  | +-------------------+ |    | +------v--------+ |
| |     prompts/      | | |  |          |            |    | |   finetune/   | |
| | * recon.md        | | |  | +--------v----------+ |    | | * packager    | |
| | * exploit.md      | | |  | |  verification/   | |    | +---------------+ |
| | * scan.md         | | |  | | * root_check     | |    +-------------------+
| | * verify.md       | | |  | +-------------------+ |
| | * escalate.md     | | |  |                       |
| | * adb_abuse.md    | | |  | +-------------------+ |
| | * persistence.md  | | |  | |    governance     | |
| +-------------------+ | |  | | * safety_tiers    | |
|                       | |  | | * blocklists      | |
| +-------------------+ | |  | +-------------------+ |
| |      memory/      | | |  |                       |
| | * vector_store    | | |  | +-------------------+ |
| | * working_memory  | | |  | |     exploits/     | |
| +-------------------+ | |  | | * attack_chain    | |
+-----------------------+ |  | | * nvd_live_match  | |
                          |  | +-------------------+ |
                          |  |                       |
                          |  | +-------------------+ |
                          |  | |     traffic/      | |
                          |  | | * mitm_controller | |
                          |  | +-------------------+ |
                          |  +-----------------------+
                          |
                          +---> Execution Flow
```

## Framework vs Engine

```
+------------------------------------------------------------------------------+
|                                                                              |
|   ========================================================================   |
|   ====================  FRAMEWORK (Reusable)  ============================   |
|   ========================================================================   |
|   ==                                                                    ==   |
|   ==   Docker | Compose | Streamlit UI | Config Mgmt | LLM Abstraction  ==   |
|   ==   ADB Wrapper | Script Sandbox | Memory Store | Dojo Pipeline      ==   |
|   ==                                                                    ==   |
|   ========================================================================   |
|                                                                              |
|   ########################################################################   |
|   ######################  ENGINE (Novel IP)  #############################   |
|   ########################################################################   |
|   ##                                                                    ##   |
|   ##   Prompt Engineering | Planner/Summarizer Chain | NL->Script Gen   ##   |
|   ##   CVE Matching | Kernel Exploit Detection | Attack Chain Logic     ##   |
|   ##   Device Fingerprinting | Permission Risk Scoring | Root Verify    ##   |
|   ##   Belt Progression | Training Data Extraction | Feedback Loop      ##   |
|   ##                                                                    ##   |
|   ########################################################################   |
|                                                                              |
|   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   |
|   %%%%%%%%%%%%%%%%%%  EXTENSIBILITY POINTS  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   |
|   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   |
|   %%                                                                    %%   |
|   %%   + New CVEs          -> core/scanning/cve_matcher.py              %%   |
|   %%   + New Exploits      -> core/exploitation/techniques/*.py         %%   |
|   %%   + New Devices       -> config/emulator/*.yaml                    %%   |
|   %%   + New LLM Providers -> agent/llm_client.py                       %%   |
|   %%   + New Prompts       -> agent/prompts/*.md                        %%   |
|   %%   + New Challenges    -> dojo/curriculum/challenges/*.yaml         %%   |
|   %%                                                                    %%   |
|   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   |
|                                                                              |
+------------------------------------------------------------------------------+
```

## Technology Stack

```
+-----------------------------------------------------------------------------+
|                              TECHNOLOGY STACK                               |
+-----------------------------------------------------------------------------+
|                                                                             |
|  FRONTEND                    BACKEND                    INFRASTRUCTURE      |
|  ---------                   -------                    --------------      |
|                                                                             |
|  +-------------+            +-------------+            +-------------+      |
|  |  Streamlit  |            |   Python    |            |   Docker    |      |
|  |    8501     |            |   3.10+     |            |  Compose    |      |
|  +-------------+            +-------------+            +-------------+      |
|                                                                             |
|  AI/LLM                      ANDROID                    STORAGE             |
|  ------                      -------                    -------             |
|                                                                             |
|  +-------------+            +-------------+            +-------------+      |
|  |   OLLAMA    |            | Genymotion  |            |  ChromaDB   |      |
|  | (Default)   |            |  Emulator   |            |  (Vectors)  |      |
|  +-------------+            +-------------+            +-------------+      |
|  |   OpenAI    |            |     ADB     |                                 |
|  |   (API)     |            |   (Bridge)  |                                 |
|  +-------------+            +-------------+                                 |
|  |  Anthropic  |                                                            |
|  |   (API)     |                                                            |
|  +-------------+                                                            |
|                                                                             |
|  TRAINING                                                                   |
|  --------                                                                   |
|                                                                             |
|  +-------------+            +-------------+            +-------------+      |
|  |   PyTorch   |            |    LoRA     |            |     MLX     |      |
|  |   2.0+      |            | Fine-tuning |            |  (Apple M)  |      |
|  +-------------+            +-------------+            +-------------+      |
|                                                                             |
+-----------------------------------------------------------------------------+
```

## Directory Structure

```
AgenticART/
|-- agent/                      # LLM Agent Layer
|   |-- chains/                 # Orchestration chains
|   |   +-- android_root_chain.py
|   |-- memory/                 # State management
|   |   |-- vector_store.py
|   |   +-- working_memory.py
|   |-- prompts/                # Prompt templates (.md files)
|   |   |-- recon.md
|   |   |-- exploit.md
|   |   |-- scan.md
|   |   |-- verify.md
|   |   |-- adb_abuse.md
|   |   |-- escalate.md
|   |   +-- ...
|   |-- llm_client.py           # Multi-provider LLM interface
|   |-- planner.py              # Attack planning
|   |-- script_generator.py     # NL -> Code generation
|   +-- summarizer.py           # Output analysis
|
|-- core/                       # Core Modules
|   |-- reconnaissance/         # Device discovery
|   |   |-- device_enum.py
|   |   +-- service_discovery.py
|   |-- scanning/               # Vulnerability scanning
|   |   |-- cve_matcher.py
|   |   |-- vuln_scanner.py
|   |   +-- permission_analyzer.py
|   |-- exploitation/           # Exploit execution
|   |   |-- exploit_runner.py
|   |   +-- techniques/
|   |       |-- magisk_root.py
|   |       |-- kernel_exploits.py
|   |       |-- adb_exploits.py
|   |       +-- bootloader_unlock.py
|   |-- verification/           # Success verification
|   |   +-- root_check.py
|   |-- exploits/               # Attack chain implementations
|   |   |-- attack_chain.py
|   |   +-- nvd_live_matcher.py
|   |-- traffic/                # Network interception
|   |   +-- mitm_controller.py
|   +-- governance.py           # Safety controls
|
|-- dojo/                       # Training Data Generation
|   |-- curriculum/             # Challenge system
|   |   |-- challenger.py
|   |   |-- executor.py
|   |   |-- loader.py
|   |   |-- context_injector.py
|   |   +-- error_extractor.py
|   |-- sensei/                 # Grading and feedback
|   |   |-- grader.py
|   |   |-- sensei.py
|   |   |-- exporter.py
|   |   +-- training_extractor.py
|   |-- finetune/               # Model training
|   |   |-- packager.py
|   |   +-- config.py
|   |-- models.py               # Data structures
|   +-- test_end_to_end.py      # Integration tests
|
|-- webapp/                     # Web Interface
|   +-- app.py                  # Streamlit application
|
|-- config/                     # Configuration
|   |-- .env.example
|   |-- settings.yaml
|   +-- emulator/
|
|-- tests/                      # Test Suite
|-- scripts/                    # CLI Tools
+-- docs/                       # Documentation
```

## Data Flow Summary

```
User Request
     |
     v
+--------------------+
|    webapp/app.py   |  <-- Streamlit UI
+--------------------+
     |
     v
+--------------------+
|   agent/planner    |  <-- Strategy selection
+--------------------+
     |
     v
+------------------------+
| agent/script_generator |  <-- LLM generates code
+------------------------+
     |
     v
+--------------------+
|  core/exploitation |  <-- Execute on device
+--------------------+
     |
     v
+--------------------+
| agent/summarizer   |  <-- Analyze results
+--------------------+
     |
     +-------> Success? ---> Report
     |              |
     |              v
     |         +--------------------+
     +-------> |  dojo/sensei       |  <-- Capture training data
               +--------------------+
                    |
                    v
               +--------------------+
               | dojo/finetune      |  <-- Export for fine-tuning
               +--------------------+
```
