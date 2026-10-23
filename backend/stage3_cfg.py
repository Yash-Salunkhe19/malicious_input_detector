"""
STAGE 3 - CONTEXT FREE GRAMMAR DETECTION

Discrete Structures concept:
Context Free Grammar (CFG) - Unit V

The detector uses grammar-like production rules
to recognize structured malicious input.
"""

import re


# ============================================================
# SQL INJECTION CFG
# ============================================================

SQL_GRAMMAR = {

    "S": [
        ["SELECT", "FROM"],
        ["SELECT", "WHERE"],
        ["UNION", "SELECT"],
        ["OR", "TRUE"]
    ]
}


# ============================================================
# COMMAND INJECTION CFG
# ============================================================

COMMAND_GRAMMAR = {

    "S": [
        ["COMMAND", "SEPARATOR", "COMMAND"],
        ["COMMAND", "PIPE", "COMMAND"]
    ]
}


# ============================================================
# XSS CFG
# ============================================================

XSS_GRAMMAR = {

    "S": [
        ["OPEN_TAG", "CONTENT", "CLOSE_TAG"],
        ["EVENT_HANDLER"]
    ]
}


# ============================================================
# TOKENIZER
# ============================================================

def tokenize(text):

    tokens = []

    upper_text = text.upper()

    # SQL tokens
    if re.search(r"\bSELECT\b", upper_text):
        tokens.append("SELECT")

    if re.search(r"\bFROM\b", upper_text):
        tokens.append("FROM")

    if re.search(r"\bWHERE\b", upper_text):
        tokens.append("WHERE")

    if re.search(r"\bUNION\b", upper_text):
        tokens.append("UNION")

    if re.search(r"\bOR\b", upper_text):
        tokens.append("OR")

    if re.search(r"\b1\s*=\s*1\b", upper_text):
        tokens.append("TRUE")

    # Command tokens
    if re.search(r";", text):
        tokens.append("SEPARATOR")

    if re.search(r"\|", text):
        tokens.append("PIPE")

    # XSS tokens
    if re.search(r"<\s*script\b", text, re.IGNORECASE):
        tokens.append("OPEN_TAG")

    if re.search(r"</\s*script\s*>", text, re.IGNORECASE):
        tokens.append("CLOSE_TAG")

    if re.search(
        r"<\s*script\b.*?</\s*script\s*>",
        text,
        re.IGNORECASE | re.DOTALL
    ):
        tokens.append("CONTENT")

    if re.search(
        r"\bon(error|load|click)\s*=",
        text,
        re.IGNORECASE
    ):
        tokens.append("EVENT_HANDLER")

    return tokens


# ============================================================
# CFG DERIVATION
# ============================================================

def cfg_derivation(tokens):

    # -----------------------------------------
    # SQL Grammar
    # -----------------------------------------

    if "SELECT" in tokens and "FROM" in tokens:

        return True

    if "SELECT" in tokens and "WHERE" in tokens:

        return True

    if "UNION" in tokens and "SELECT" in tokens:

        return True

    if "OR" in tokens and "TRUE" in tokens:

        return True


    # -----------------------------------------
    # Command Injection Grammar
    # -----------------------------------------

    if "SEPARATOR" in tokens:

        return True

    if "PIPE" in tokens:

        return True


    # -----------------------------------------
    # XSS Grammar
    # -----------------------------------------

    if "OPEN_TAG" in tokens and "CLOSE_TAG" in tokens:

        return True

    if "EVENT_HANDLER" in tokens:

        return True

    return False


# ============================================================
# MAIN CFG FUNCTION
# ============================================================

def check_cfg(text):
    """
    Check whether input belongs to one of our
    malicious structured grammar patterns.

    Returns:
        True  -> CFG pattern recognized
        False -> not recognized
    """

    if not isinstance(text, str):

        return False

    if not text.strip():

        return False

    tokens = tokenize(text)

    return cfg_derivation(tokens)