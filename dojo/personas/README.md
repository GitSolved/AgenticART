# AgenticART Device Personas

## Overview

A **persona** defines what a realistic Android device should look like - the apps installed, user data present, and system configuration. This makes challenges meaningful by ensuring there's actual data to exfiltrate, apps to analyze, and credentials to capture.

Without personas, testing "exfiltrate contacts" on an empty device proves nothing.

## Persona Structure

```yaml
name: "Persona Name"
description: "What this persona simulates"
compatibility: android_11  # or android_14, universal

device:
  # Hardware/software identity

apps:
  # Installed applications

user_data:
  # Contacts, SMS, files, etc.

security:
  # Lock screen, permissions, etc.
```

## Available Personas

| Persona | Android | Description |
|---------|---------|-------------|
| `base_persona.yaml` | universal | Common settings inherited by all personas |
| `android_11_user.yaml` | 11 | Everyday smartphone user |
| `android_14_user.yaml` | 14 | Modern device user |
| `enterprise_user.yaml` | universal | Corporate device with MDM |

## Usage

### 1. Provision a Device

```bash
# Provision device with Android 11 user persona
python dojo/personas/setup/provision_device.py android_11_user

# Validate device matches persona
python dojo/personas/setup/validate_persona.py android_11_user
```

### 2. Challenge Integration

Challenges can specify persona requirements:

```yaml
- id: orange_data_001
  name: "Contact Exfiltration"
  persona_requirements:
    min_contacts: 50
    required_apps:
      - com.whatsapp
```

The challenge runner will:
1. Check if device matches persona requirements
2. Skip challenges if requirements not met
3. Report persona validation in results

## Persona Categories

### Device Identity
- Model, manufacturer, fingerprint
- IMEI pattern (for realism)
- Build properties

### Installed Apps

| Category | Examples | Challenge Relevance |
|----------|----------|---------------------|
| Banking | Chase, Venmo, PayPal | Credential theft, traffic interception |
| Social | Instagram, Twitter, TikTok | Data exfiltration, token theft |
| Messaging | WhatsApp, Signal, Telegram | Message interception |
| Productivity | Gmail, Drive, Office | Corporate data access |
| Security | Authenticator apps | 2FA bypass |

### User Data

| Data Type | Purpose |
|-----------|---------|
| Contacts | Exfiltration targets, social engineering |
| SMS | 2FA codes, sensitive notifications |
| Photos | Privacy breach demonstration |
| Files | Document theft scenarios |
| WiFi | Network credential extraction |
| Browser | Session hijacking, history theft |

### Security Configuration

| Setting | Realistic State |
|---------|-----------------|
| Lock Screen | PIN or pattern enabled |
| Biometrics | Fingerprint configured |
| Developer Options | Enabled (for testing) |
| USB Debugging | Enabled (for ADB access) |
| Unknown Sources | Enabled |

## Data Generation

The provisioning scripts generate realistic-looking data:

- **Contacts**: Random names with proper phone number formats
- **SMS**: Mix of normal messages and sensitive ones (2FA, bank alerts)
- **Photos**: Stock images or generated placeholders
- **Files**: Sample PDFs, documents with realistic names

All generated data is clearly fake but structured like real data.

## Extending Personas

To create a new persona:

1. Copy an existing persona YAML
2. Modify for your use case
3. Add to `dojo/personas/`
4. Test with `validate_persona.py`

## Security Notes

- Personas contain NO real personal data
- All phone numbers use reserved test ranges
- All names are randomly generated
- Banking apps are mocked or use test accounts
- WiFi passwords are dummy values
