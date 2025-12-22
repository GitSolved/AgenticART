"""
Shared Constants and Regex Patterns
"""

import re

# High-value target patterns (credentials, tokens, secrets)
CREDENTIAL_PATTERNS = [
    r'(?:password|passwd|pwd|key|secret|token|auth)[=:\s]+([^\s,\]"]+)',
    r'(?:password|passwd|pwd|key|secret|token|auth)[^>]*>([^<]+)<',  # XML/HTML
    r'(?:password|passwd|pwd|key|secret|token|auth).*?["\'>]([^"\'<]+)',
]

# Regex objects for efficiency
CRED_REGEXES = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]

# User identity patterns
USER_PATTERNS = [
    r'(?:user|username|email|account)[=:\s]+([^\s,\]"]+)',
]
USER_REGEXES = [re.compile(p, re.IGNORECASE) for p in USER_PATTERNS]

# Common sensitive Android paths
SENSITIVE_PATHS = [
    "shared_prefs/",
    "databases/",
    "files/",
]
