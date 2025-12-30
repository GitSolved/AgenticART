# Challenge Format

Structure of AgenticART challenge definitions.

## YAML Structure

```yaml
id: "green_042"
belt: green
title: "Content Provider SQL Injection"
category: "content_provider"

description: |
  The target app exposes a content provider that is vulnerable
  to SQL injection. Extract user credentials from the database.

objective: |
  Successfully extract credentials via SQL injection
  through the content provider URI.

inputs:
  target_package: "com.vulnerable.app"
  content_uri: "content://com.vulnerable.app.provider/users"

  additional_context:
    cve_id: "CVE-2023-XXXXX"
    cvss_score: 7.5
    affected_versions: "1.0.0 - 1.2.3"

expected_output:
  contains:
    - "username"
    - "password"

validation:
  type: "output_contains"
  patterns:
    - "admin"
    - "credentials"

hints:
  - "Content providers can be queried with 'content query'"
  - "SQL injection payloads: ' OR '1'='1"
  - "Try projection parameter for injection"

execution_mode: "full_execution"
difficulty: 3
estimated_time: 300  # seconds
```

## Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (belt_number) |
| `belt` | Yes | Difficulty level |
| `title` | Yes | Short description |
| `category` | Yes | Technique category |
| `description` | Yes | Full context |
| `objective` | Yes | Success criteria |
| `inputs` | Yes | Challenge parameters |
| `expected_output` | No | Output validation |
| `validation` | No | Grading rules |
| `hints` | No | Progressive hints |
| `execution_mode` | Yes | How to execute |

## Execution Modes

| Mode | Description |
|------|-------------|
| `full_execution` | Complete challenge on device |
| `detection_analysis` | Analyze but don't exploit |
| `detection_only` | Vulnerability assessment |
| `syntax_only` | Validate code syntax |
| `simulation` | Behavior simulation |

## Categories

| Category | Belt Range | Examples |
|----------|------------|----------|
| `device_recon` | White-Yellow | Version checks, package lists |
| `permission_bypass` | Orange-Green | Exported components |
| `content_provider` | Green-Blue | SQL injection, path traversal |
| `intent_attack` | Green-Blue | Deep links, IPC |
| `memory_corruption` | Brown-Black | Buffer overflow, UAF |
| `kernel` | Black | Privilege escalation |

## Adding Custom Challenges

1. Create YAML in appropriate belt folder:
   ```
   dojo/curriculum/green_belt/challenges.yaml
   ```

2. Follow the schema above

3. Validate:
   ```bash
   python3 -c "from dojo.curriculum.loader import load_challenges; load_challenges('green')"
   ```
