"""
SHARED PREPROCESSOR MODULE
Ensures identical text preprocessing between training and runtime inference.
"""

import re
import unicodedata


def clean_text(text: str) -> str:
    """
    Standardize input text for feature extraction and ML classification.
    - Converts to string and lowercases.
    - Normalizes unicode characters (NFKC).
    - Replaces carriage returns, newlines, and tabs with spaces.
    - Collapses multiple whitespace characters.
    - Strips leading and trailing whitespace.
    
    NOTE: We preserve punctuation, operators, quotes, and symbols because
    they are vital signals for SQLi, XSS, and injection detection.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Normalize unicode (e.g., full-width characters)
    text = unicodedata.normalize("NFKC", text)
    text = text.lower()

    # Normalize newlines and tabs to spaces
    text = re.sub(r"[\r\n\t]+", " ", text)

    # Collapse multiple whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text
