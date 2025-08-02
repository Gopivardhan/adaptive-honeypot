"""
Fingerprint detection module.

This module contains helper functions that attempt to identify the tools and
behaviours of incoming connections based on headers, payloads and request
patterns. The heuristics here are intentionally simple but demonstrate how
attackers can be fingerprinted without running the risk of exploitation. To
extend detection capabilities, additional signatures could be loaded from a
configuration file or implemented as machine learning models.
"""

from __future__ import annotations

from typing import Dict, List, Optional


def detect_tool(headers: Dict[str, str], payload: Optional[str], path: Optional[str], request_type: str) -> Optional[str]:
    """Infer the scanning tool or attack framework from request metadata.

    Parameters
    ----------
    headers:
        HTTP headers or command metadata from the client.
    payload:
        Raw body or command payload.
    path:
        Request URI or command path.
    request_type:
        High-level request type (e.g. GET, POST, USER, PASS).

    Returns
    -------
    str or None
        A short string identifier for the detected tool (e.g. 'sqlmap'). None if
        no signature could be derived.
    """
    ua = headers.get("User-Agent", "").lower() if headers else ""
    if not ua and payload:
        # Some scanners such as nmap send raw payloads; look for names
        ua = payload.lower()

    # Common scanner signatures in user agents
    scanner_signatures = {
        "sqlmap": ["sqlmap"],
        "nikto": ["nikto"],
        "nmap": ["nmap", "libwww-perl", "python-requests"] ,
        "w3af": ["w3af"],
        "acunetix": ["acunetix"],
        "nessus": ["nessus"],
    }
    for tool, patterns in scanner_signatures.items():
        for pat in patterns:
            if pat in ua:
                return tool

    # Inspect paths that hint at certain tools
    if path:
        lower_path = path.lower()
        if "wp-login" in lower_path or "wp-admin" in lower_path:
            return "wordpress_scanner"
        if "phpmyadmin" in lower_path:
            return "phpmyadmin_scanner"
        if "/etc/passwd" in lower_path:
            return "file_inclusion"

    # Examine payload for SQL injection payloads
    if payload:
        lower_payload = payload.lower()
        sql_keywords = ["select", "union", "sleep", "benchmark", "load_file", "into outfile"]
        if any(kw in lower_payload for kw in sql_keywords):
            return "sql_injection"

    return None


def classify_client(history: List[dict], current_tool: Optional[str]) -> str:
    """Classify the client as human, bot or scanner based on history and tool.

    Parameters
    ----------
    history:
        List of recent event dictionaries for this client IP.
    current_tool:
        The tool signature detected for the current event.

    Returns
    -------
    str
        One of 'human', 'bot', 'scanner'.
    """
    if current_tool:
        # Known tool indicates a scanner
        return "scanner"
    # If many rapid requests in a short time, treat as bot
    if len(history) >= 5:
        # Check if more than 5 requests have occurred within last 2 seconds
        timestamps = [event["timestamp"] for event in history[-5:]]
        try:
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
            times = [datetime.fromisoformat(t) for t in timestamps]
            if (max(times) - min(times)).total_seconds() < 2:
                return "bot"
        except Exception:
            pass
    return "human"
