"""
STAGE 1 - RULE BASED DETECTION

Uses regular expressions to detect common malicious
input patterns.

Discrete Structures concept:
Regular Expressions (Unit IV)
"""

import re


# Common malicious patterns
MALICIOUS_PATTERNS = [

    # -------------------------
    # SQL Injection
    # -------------------------
    r"(?i)\bunion\b\s+\bselect\b",
    r"(?i)\bselect\b.*\bfrom\b",
    r"(?i)\bor\b\s+1\s*=\s*1",
    r"(?i)\band\b\s+1\s*=\s*1",
    r"(?i)'\s*or\s*'.*'='",

    # -------------------------
    # XSS
    # -------------------------
    r"(?i)<\s*script.*?>",
    r"(?i)</\s*script\s*>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onclick\s*=",

    # -------------------------
    # Command Injection
    # -------------------------
    r";\s*(ls|dir|cat|whoami|pwd)",
    r"\|\s*(ls|dir|cat|whoami|pwd)",
    r"&&\s*(ls|dir|cat|whoami|pwd)",

    # -------------------------
    # Path Traversal
    # -------------------------
    r"\.\./",
    r"\.\.\\",

    # -------------------------
    # Dangerous system commands
    # -------------------------
    r"(?i)\b(rm\s+-rf|wget|curl|chmod|shutdown)\b"
]


def rule_based_detection(text):
    """
    Stage 1:
    Check input against malicious regular expressions.

    Returns:
        True  -> malicious pattern detected
        False -> no pattern detected
    """

    if not isinstance(text, str):
        return False

    for pattern in MALICIOUS_PATTERNS:

        if re.search(pattern, text):
            return True

    return False