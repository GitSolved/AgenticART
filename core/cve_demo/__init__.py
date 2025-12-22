"""
Exploit Templates and 1-Day Demonstration System

Provides:
- Exploit templates for common Android vulnerability classes
- PoC fetcher for GitHub/ExploitDB
- 1-day vulnerability demonstrator
"""

from .templates import ExploitTemplate, VulnerabilityClass, get_template
from .poc_fetcher import PoCFetcher, PoCSource
from .demonstrator import OneDayDemonstrator

__all__ = [
    "ExploitTemplate",
    "VulnerabilityClass",
    "get_template",
    "PoCFetcher",
    "PoCSource",
    "OneDayDemonstrator",
]
