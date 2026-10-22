"""Agent A - Log Analyst (Phase 2).

Reads log files and identifies IP addresses with repeated failed logins.
Uses pandas and regex to count occurrences.
Note: Agent A has read-only access and cannot execute any remediation actions.
"""
import re
from pathlib import Path
from typing import Union

import pandas as pd

# Default log file path next to this script
LOG_FILE = Path(__file__).parent / "server_logs.txt"

# Default threshold for suspicious failed attempts
THRESHOLD = 3

# Regex to capture IP addresses from failed SSH login attempts
# Matches lines like: "Failed password for root from 203.0.113.5 port ..."
# or "Failed password for invalid user admin from 203.0.113.5 port ..."
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password .* from (\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_logs(path: Union[str, Path] = LOG_FILE, threshold: int = 3) -> dict[str, int]:
    """Read a log file, count failed logins per IP, and return IPs with count >= threshold.
    
    Args:
        path: Path to the log file.
        threshold: Minimum number of failed logins to be considered suspicious.
        
    Returns:
        dict: Mapping of {ip: count} for all IPs meeting or exceeding the threshold.
    """
    log_path = Path(path)
    if not log_path.exists():
        return {}

    ips: list[str] = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ips.append(match.group(1))

    # If no failed logins found at all, return empty dict
    if not ips:
        return {}

    # Use pandas to count occurrences of each IP
    counts = pd.Series(ips).value_counts()
    suspicious = counts[counts >= threshold]

    # Convert to native Python int for clean JSON serialization
    return {ip: int(n) for ip, n in suspicious.items()}


def run_analysis() -> dict[str, int]:
    """Convenience wrapper for backwards compatibility with Phase 1."""
    return analyze_logs(LOG_FILE, THRESHOLD)
