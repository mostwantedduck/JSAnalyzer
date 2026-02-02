# -*- coding: utf-8 -*-
"""
Pattern Loader for JS Analyzer - Burp Suite Extension
Loads and compiles regex patterns from patterns.json configuration file.
"""

import json
import re
import os


def _get_flags(flags_str):
    """Convert flag string to re flags."""
    flags = 0
    if flags_str:
        if "i" in flags_str.lower():
            flags |= re.IGNORECASE
    return flags


def _compile_pattern(pattern_obj):
    """Compile a single pattern from config."""
    if isinstance(pattern_obj, str):
        return re.compile(pattern_obj)
    elif isinstance(pattern_obj, dict):
        pattern = pattern_obj.get("pattern", "")
        flags = _get_flags(pattern_obj.get("flags", ""))
        return re.compile(pattern, flags)
    return None


def load_patterns(config_path=None):
    """
    Load and compile regex patterns from JSON config.

    Args:
        config_path: Optional path to patterns.json. If None, uses default location.

    Returns:
        Dictionary with compiled pattern lists.
    """
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "patterns.json")

    with open(config_path, "r") as f:
        config = json.load(f)

    # Compile endpoint patterns
    endpoint_patterns = []
    for p in config.get("endpoint_patterns", []):
        compiled = _compile_pattern(p)
        if compiled:
            endpoint_patterns.append(compiled)

    # Compile URL patterns
    url_patterns = []
    for p in config.get("url_patterns", []):
        compiled = _compile_pattern(p)
        if compiled:
            url_patterns.append(compiled)

    # Compile secret patterns (with labels)
    secret_patterns = []
    for p in config.get("secret_patterns", []):
        if isinstance(p, dict):
            compiled = _compile_pattern(p)
            label = p.get("label", "Unknown Secret")
            if compiled:
                secret_patterns.append((compiled, label))

    # Compile low confidence secret patterns (with labels)
    secret_patterns_low = []
    for p in config.get("secret_patterns_low_confidence", []):
        if isinstance(p, dict):
            compiled = _compile_pattern(p)
            label = p.get("label", "Unknown Secret")
            if compiled:
                secret_patterns_low.append((compiled, label))

    # Compile email pattern
    email_pattern = None
    email_str = config.get("email_pattern", "")
    if email_str:
        email_pattern = re.compile(email_str)

    # Compile file patterns
    file_patterns = []
    for p in config.get("file_patterns", []):
        compiled = _compile_pattern(p)
        if compiled:
            file_patterns.append(compiled)

    return {
        "ENDPOINT_PATTERNS": endpoint_patterns,
        "URL_PATTERNS": url_patterns,
        "SECRET_PATTERNS": secret_patterns,
        "SECRET_PATTERNS_LOW_CONFIDENCE": secret_patterns_low,
        "EMAIL_PATTERN": email_pattern,
        "FILE_PATTERNS": file_patterns,
    }


# For testing standalone
if __name__ == "__main__":
    try:
        patterns = load_patterns()
        print("Patterns loaded successfully!")
        print("  ENDPOINT_PATTERNS: %d patterns" % len(patterns["ENDPOINT_PATTERNS"]))
        print("  URL_PATTERNS: %d patterns" % len(patterns["URL_PATTERNS"]))
        print("  SECRET_PATTERNS: %d patterns" % len(patterns["SECRET_PATTERNS"]))
        print(
            "  EMAIL_PATTERN: %s"
            % ("loaded" if patterns["EMAIL_PATTERN"] else "not loaded")
        )
        print("  FILE_PATTERNS: %d patterns" % len(patterns["FILE_PATTERNS"]))
    except Exception as e:
        print("Error loading patterns: %s" % str(e))
