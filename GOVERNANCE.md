# Security Governance Policy

## Scope & Authorization

This framework is authorized for use ONLY against:

### Approved Targets
- **Lab environments** running on isolated networks
- **Genymotion/Android emulators** on local machine
- **Explicitly authorized test devices** with written permission
- **CTF (Capture The Flag)** challenges and training environments

### Network Restrictions
```yaml
allowed_networks:
  - 127.0.0.0/8        # Localhost
  - 10.0.0.0/8         # Private (lab VLANs)
  - 172.16.0.0/12      # Private (Docker networks)
  - 192.168.0.0/16     # Private (home/lab networks)

blocked_networks:
  - 0.0.0.0/0          # Default deny all public
  - production/*       # Any production environment
  - *.corp.company.com # Corporate infrastructure
```

### Explicitly Prohibited
- Production systems of any kind
- Systems without explicit written authorization
- Third-party infrastructure without permission
- Public cloud resources (unless isolated lab accounts)
- Any system that could affect real users or data

---

## Triage Levels

All generated exploits must be classified:

| Level | Name | Description | Approval Required |
|-------|------|-------------|-------------------|
| 1 | **INFO** | Read-only reconnaissance (nmap, getprop) | Auto-approve |
| 2 | **LOW** | Non-destructive enumeration (pm list, dumpsys) | Auto-approve |
| 3 | **MEDIUM** | State-changing but reversible (CONFIG SET) | Human review |
| 4 | **HIGH** | Privilege escalation, persistence | Human approval |
| 5 | **CRITICAL** | Destructive, data exfiltration, lateral movement | Explicit sign-off |

---

## Human-in-the-Loop Requirements

### Mandatory Review Points
1. **Before any script execution** - User must approve
2. **Before any network connection** - Validate target is in allowed list
3. **Before any file write** - Confirm target path is safe
4. **Before any privilege escalation** - Explicit acknowledgment

### Approval Format
```
[APPROVAL REQUIRED]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Action:      CONFIG SET dir /data/local/tmp
Target:      127.0.0.1:6379 (Redis)
Triage:      MEDIUM (Level 3)
Risk:        Changes Redis configuration, reversible
Governance:  ✅ Target in allowed network (127.0.0.0/8)

Commands to execute:
┌──────────────────────────────────────────────────────────────┐
│ redis-cli -h 127.0.0.1 CONFIG SET dir /data/local/tmp       │
│ redis-cli -h 127.0.0.1 CONFIG SET dbfilename exploit.rdb    │
└──────────────────────────────────────────────────────────────┘

[A]pprove  [R]eject  [M]odify  [E]xplain
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## AI Behavioral Constraints

When generating or executing exploits, the AI MUST:

1. **Check governance first** - Validate target against allowed networks
2. **Assess triage level** - Classify action severity before proceeding
3. **Request approval** - Never execute Level 3+ without human consent
4. **Log all actions** - Maintain audit trail in output/logs/
5. **Respect rejections** - If user rejects, stop and explain alternatives

### System Prompt Injection
The AI should be reminded of these constraints via system prompt:
```
You are bound by GOVERNANCE.md. Before any action:
1. Verify target is in allowed_networks
2. Classify triage level (1-5)
3. If level >= 3, request human approval
4. Never proceed without explicit consent for destructive actions
```

---

## Audit Requirements

All sessions must log:
- Timestamp
- Target IP/device
- Action attempted
- Triage level
- Approval status (approved/rejected/auto)
- Execution result
- Operator identity (if available)

Logs stored in: `output/logs/audit_YYYYMMDD.jsonl`

---

## Incident Response

If an action affects an unauthorized target:
1. **STOP** all automated execution immediately
2. **DOCUMENT** what happened
3. **NOTIFY** security team
4. **PRESERVE** all logs
5. **DO NOT** attempt to "fix" or hide the incident

---

## Acknowledgment

By using this framework, operators acknowledge:
- They have authorization for all targets
- They understand the triage levels
- They accept responsibility for approving actions
- They will maintain audit logs

Last Updated: 2024-12-20
