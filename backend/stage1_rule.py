"""
STAGE 1 - REGULAR EXPRESSION / RULE-BASED DETECTION
===================================================
Discrete Structures concept:
Regular Expressions and Regular Languages (Unit IV)

Features:
- Pre-compiled regular expressions for high performance.
- Structured rule catalog covering:
    * SQL Injection (SQLi)
    * Cross-Site Scripting (XSS)
    * Path Traversal
    * Operating System Command Injection
- Differentiates attack categories and returns matched rule IDs and explanations.
- Precise anchoring and boundary checks to prevent false positives on ordinary words.
"""

import re
from typing import Dict, List, Any


RULES: List[Dict[str, Any]] = [
    # ========================================================
    # SQL INJECTION (SQLi)
    # ========================================================
    {
        "id": "SQLI_UNION_SELECT",
        "name": "SQL UNION SELECT Injection",
        "category": "SQL Injection",
        "description": "Attempts to combine query results with arbitrary database tables using UNION SELECT.",
        "regex": re.compile(r"(?i)\bUNION\b(?:\s+ALL)?\s+\bSELECT\b"),
        "example": "' UNION SELECT null, username, password FROM users --"
    },
    {
        "id": "SQLI_TAUTOLOGY_OR",
        "name": "SQL Tautology / Boolean Bypass (OR 1=1)",
        "category": "SQL Injection",
        "description": "Injects an always-true boolean condition (e.g., OR 1=1 or 'a'='a') to bypass authentication.",
        "regex": re.compile(r"(?i)(?:'|\")?\s*\bOR\b\s+(?:(?:\d+\s*=\s*\d+)|(?:'[^']*'\s*=\s*'[^']*'?)|(?:\"[^\"]*\"\s*=\s*\"[^\"]*\"?)|(?:'?[a-zA-Z0-9_]+'?\s*=\s*'?[a-zA-Z0-9_]+'?))"),
        "example": "admin' OR 1=1 --"
    },
    {
        "id": "SQLI_TAUTOLOGY_AND",
        "name": "SQL Tautology Verification (AND 1=1)",
        "category": "SQL Injection",
        "description": "Blind SQL injection probing condition using always-true AND verification.",
        "regex": re.compile(r"(?i)(?:'|\")?\s*\bAND\b\s+(?:(?:\d+\s*=\s*\d+)|(?:'[^']*'\s*=\s*'[^']*'?)|(?:\"[^\"]*\"\s*=\s*\"[^\"]*\"?)|(?:'?[a-zA-Z0-9_]+'?\s*=\s*'?[a-zA-Z0-9_]+'?))"),
        "example": "1' AND 1=1 --"
    },
    {
        "id": "SQLI_COMMENT_TERMINATOR",
        "name": "SQL Comment / Query Termination",
        "category": "SQL Injection",
        "description": "Trunctates the rest of the original query using SQL comment markers (-- or /* ... */).",
        "regex": re.compile(r"(?:--\s*$|--\s*[\w\s]|[;]\s*--|/\*.*?\*/)"),
        "example": "admin' --"
    },
    {
        "id": "SQLI_STACKED_QUERIES",
        "name": "SQL Stacked Query / DDL Execution",
        "category": "SQL Injection",
        "description": "Terminates the active statement and attempts to execute secondary statements (DROP, INSERT, UPDATE, DELETE).",
        "regex": re.compile(r"(?i);\s*(?:DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"),
        "example": "; DROP TABLE users; --"
    },
    {
        "id": "SQLI_SLEEP_DELAY",
        "name": "SQL Time-Based Blind Injection",
        "category": "SQL Injection",
        "description": "Forces database thread delays (SLEEP, PG_SLEEP, WAITFOR DELAY) to infer data through response latency.",
        "regex": re.compile(r"(?i)\b(?:SLEEP\s*\(\s*\d+\s*\)|PG_SLEEP\s*\(\s*\d+\s*\)|WAITFOR\s+DELAY\s*'\d+:\d+:\d+')"),
        "example": "' OR SLEEP(5) --"
    },

    # ========================================================
    # CROSS-SITE SCRIPTING (XSS)
    # ========================================================
    {
        "id": "XSS_SCRIPT_TAG",
        "name": "XSS Script Tag Injection",
        "category": "Cross-Site Scripting (XSS)",
        "description": "Embeds executable JavaScript blocks via <script> tags.",
        "regex": re.compile(r"(?i)<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>|<\s*script\b[^>]*>"),
        "example": "<script>alert(1)</script>"
    },
    {
        "id": "XSS_EVENT_HANDLER",
        "name": "XSS Inline Event Handler",
        "category": "Cross-Site Scripting (XSS)",
        "description": "Triggers unauthorized scripts through HTML tag attributes (onerror, onload, onclick, onmouseover).",
        "regex": re.compile(r"(?i)\b(onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=\s*['\"]?[^'\">]+"),
        "example": "<img src=x onerror=alert(document.cookie)>"
    },
    {
        "id": "XSS_JAVASCRIPT_URI",
        "name": "XSS Pseudo-Protocol URI",
        "category": "Cross-Site Scripting (XSS)",
        "description": "Executes script via URI handlers (javascript: or vbscript:).",
        "regex": re.compile(r"(?i)\b(?:javascript|vbscript|data\s*:\s*text/html)\s*:\s*"),
        "example": "javascript:alert(1)"
    },
    {
        "id": "XSS_IFRAME_EMBED",
        "name": "XSS Malicious Frame / Object Embed",
        "category": "Cross-Site Scripting (XSS)",
        "description": "Embeds malicious third-party frames or objects using <iframe> or <object> tags.",
        "regex": re.compile(r"(?i)<\s*(?:iframe|object|embed)\b[^>]*>"),
        "example": "<iframe src='http://evil.com'></iframe>"
    },

    # ========================================================
    # PATH TRAVERSAL / LOCAL FILE INCLUSION
    # ========================================================
    {
        "id": "PATH_TRAVERSAL_DIR_JUMP",
        "name": "Path Traversal Directory Escape",
        "category": "Path Traversal",
        "description": "Uses relative directory jumps (../ or ..\\) to escape web root directories.",
        "regex": re.compile(r"(?:\.\.[/\\])+"),
        "example": "../../../etc/passwd"
    },
    {
        "id": "PATH_TRAVERSAL_SENSITIVE_FILE",
        "name": "Path Traversal Sensitive File Target",
        "category": "Path Traversal",
        "description": "Directly targets operating system credential stores or configuration files (etc/passwd, windows/win.ini).",
        "regex": re.compile(r"(?i)(?:/etc/(?:passwd|shadow|hosts)|boot\.ini|windows[/\\]system32)"),
        "example": "/etc/passwd"
    },

    # ========================================================
    # OPERATING SYSTEM COMMAND INJECTION
    # ========================================================
    {
        "id": "CMD_CHAIN_DELIMITER",
        "name": "OS Command Chaining Operator",
        "category": "Command Injection",
        "description": "Appends secondary shell commands using control operators (;, |, ||, &&) combined with command execution.",
        "regex": re.compile(r"(?:[;&|`$]|\b&&\b)\s*(?:cat|ls|dir|whoami|id|pwd|uname|netcat|nc|curl|wget|bash|sh|cmd|powershell)\b"),
        "example": "; cat /etc/passwd"
    },
    {
        "id": "CMD_DANGEROUS_SYSTEM_CALL",
        "name": "Dangerous OS Command Invocation",
        "category": "Command Injection",
        "description": "Direct invocation of destructive system utilities (rm -rf, shutdown, useradd, chmod).",
        "regex": re.compile(r"(?i)\b(?:rm\s+-(?:r|f|rf|fr)\b|shutdown\s+-(?:r|h|s)\b|mkfs\b|dd\s+if=)"),
        "example": "rm -rf /var/log"
    }
]


def rule_based_detection(text: str) -> Dict[str, Any]:
    """
    Stage 1:
    Evaluate input against compiled regular expression rules.

    Returns:
        dict with:
            matched (bool)
            matches (list of matched rule dicts with id, name, category, explanation, match_text)
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "matched": False,
            "matches": [],
            "count": 0
        }

    matches = []
    for rule in RULES:
        found = rule["regex"].search(text)
        if found:
            matches.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "category": rule["category"],
                "explanation": rule["description"],
                "matched_text": found.group(0),
                "span": list(found.span())
            })

    return {
        "matched": len(matches) > 0,
        "matches": matches,
        "count": len(matches)
    }


def get_all_rules() -> List[Dict[str, Any]]:
    """Return all defined rules with pattern strings for documentation and playground."""
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "category": r["category"],
            "description": r["description"],
            "pattern": r["regex"].pattern,
            "example": r["example"]
        }
        for r in RULES
    ]