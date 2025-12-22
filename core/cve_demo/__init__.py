"""
Exploit Templates and 1-Day Demonstration System

Provides:
- Exploit templates for common Android vulnerability classes
- PoC fetcher for GitHub/ExploitDB
- 1-day vulnerability demonstrator
"""

from .demonstrator import OneDayDemonstrator
from .poc_fetcher import PoCFetcher, PoCSource
from .templates import ExploitTemplate, VulnerabilityClass, get_template

__all__ = [
    "ExploitTemplate",
    "VulnerabilityClass",
    "get_template",
    "PoCFetcher",
    "PoCSource",
    "OneDayDemonstrator",
]
