"""
URL AND API PARAMETER STATIC SCANNER
====================================
Performs deep static analysis on URL endpoints, query parameters, and path segments
without making outbound network requests or executing arbitrary code.

Features:
- Robust parsing of schemes, netlocs, paths, query strings, and fragments.
- Recursive URL decoding (unquote_plus) to catch double-encoded attack strings.
- Independent analysis of query parameter names vs parameter values.
- Deep inspection of path segments for path traversal (../) and file inclusion.
- Prevents false-positive flags on common parameter names (id, page, admin, login).
- Returns structured security telemetry and normalized components.
"""

from urllib.parse import urlsplit, parse_qs, unquote_plus
from typing import Dict, Any, List

from backend.pipeline import detect_input


# Common benign parameter keys that should not trigger false alarms
BENIGN_PARAM_NAMES = {"id", "page", "limit", "offset", "sort", "order", "q", "query", "search", "lang", "ref", "view", "tab", "filter", "category", "user", "username", "redirect"}


def scan_url(url: str, http_method: str = "GET") -> Dict[str, Any]:
    """
    Statically analyzes a URL and its components for malicious injection payloads.
    Does NOT make any network connections.
    """
    raw_url = (url or "").strip()

    if not raw_url:
        return {
            "url": url,
            "is_valid": False,
            "result": "Invalid URL",
            "risk_level": "None",
            "explanation": "No URL provided for analysis.",
            "components": {},
            "stages": {"regex": False, "dfa": False, "cfg": False, "ml": False},
            "suspicious_parameters": [],
            "parameter_analysis": {},
            "path_analysis": None,
            "disclaimer": "Static analysis inspects lexical syntax and cannot guarantee runtime security."
        }

    # Handle missing scheme gracefully for parsing
    has_scheme = raw_url.startswith(("http://", "https://", "ftp://", "ws://", "wss://"))
    url_to_parse = raw_url if has_scheme else ("http://" + raw_url)

    try:
        parsed = urlsplit(url_to_parse)
    except Exception as exc:
        return {
            "url": url,
            "is_valid": False,
            "result": "Malformed URL",
            "risk_level": "Low",
            "explanation": f"URL could not be parsed: {str(exc)}",
            "components": {},
            "stages": {"regex": False, "dfa": False, "cfg": False, "ml": False},
            "suspicious_parameters": [],
            "parameter_analysis": {},
            "path_analysis": None,
            "disclaimer": "Static analysis inspects lexical syntax and cannot guarantee runtime security."
        }

    stages = {"regex": False, "dfa": False, "cfg": False, "ml": False}
    suspicious_params: List[str] = []
    param_analysis: Dict[str, Any] = {}
    explanations: List[str] = []
    malicious_found = False

    def merge_stages(detection_stages: Dict[str, bool]):
        for key in ("regex", "dfa", "cfg", "ml"):
            if detection_stages.get(key, False):
                stages[key] = True

    # 1. Path Segment Analysis
    decoded_path = unquote_plus(parsed.path or "")
    path_detection = None
    if decoded_path and decoded_path != "/":
        path_detection = detect_input(decoded_path)
        if path_detection.get("result") == "Malicious":
            # For paths, we trust deterministic rules (e.g. ../ or script tags)
            if any(path_detection["stages"][s] for s in ("regex", "dfa", "cfg")):
                malicious_found = True
                merge_stages(path_detection["stages"])
                explanations.append(f"Suspicious path segment detected: {path_detection.get('explanation')}")

    # 2. Query Parameter Analysis
    raw_query = parsed.query or ""
    query_params = parse_qs(raw_query, keep_blank_values=True)

    for param_name, values in query_params.items():
        clean_param_name = unquote_plus(param_name)
        param_findings = []

        # Analyze parameter name itself (e.g. prototype pollution or command injection in key)
        if clean_param_name.lower() not in BENIGN_PARAM_NAMES:
            name_detection = detect_input(clean_param_name)
            if name_detection.get("result") == "Malicious" and any(name_detection["stages"][s] for s in ("regex", "dfa", "cfg")):
                malicious_found = True
                merge_stages(name_detection["stages"])
                suspicious_params.append(f"{clean_param_name} (parameter name)")
                param_findings.append({
                    "target": "name",
                    "value": clean_param_name,
                    "result": name_detection
                })
                explanations.append(f"Parameter name '{clean_param_name}' matched malicious signature.")

        # Analyze each parameter value
        for val in values:
            decoded_val = unquote_plus(val)
            # Also test double-decoded value if encoded multiple times
            double_decoded = unquote_plus(decoded_val)
            test_val = double_decoded if double_decoded != decoded_val else decoded_val

            val_detection = detect_input(test_val)
            is_val_mal = (val_detection.get("result") == "Malicious")
            
            if is_val_mal:
                malicious_found = True
                merge_stages(val_detection["stages"])
                if clean_param_name not in suspicious_params:
                    suspicious_params.append(clean_param_name)
                explanations.append(
                    f"Parameter '{clean_param_name}' contains malicious payload ({val_detection.get('finding_type')}): {val_detection.get('explanation')}"
                )

            param_findings.append({
                "target": "value",
                "raw_value": val,
                "decoded_value": decoded_val,
                "result": val_detection
            })

        param_analysis[clean_param_name] = param_findings

    # 3. Fragment Analysis
    decoded_fragment = unquote_plus(parsed.fragment or "")
    if decoded_fragment:
        frag_detection = detect_input(decoded_fragment)
        if frag_detection.get("result") == "Malicious" and any(frag_detection["stages"][s] for s in ("regex", "dfa", "cfg")):
            malicious_found = True
            merge_stages(frag_detection["stages"])
            explanations.append(f"URL fragment contains malicious payload: {frag_detection.get('explanation')}")

    overall_result = "Malicious" if malicious_found else "Safe"
    risk_level = "High" if any(stages[s] for s in ("regex", "dfa", "cfg")) else ("Medium" if stages["ml"] else "None")

    if not explanations:
        if overall_result == "Safe":
            explanations.append(
                f"No malicious SQLi, XSS, Path Traversal, or Command Injection patterns detected across {len(query_params)} query parameters and path segments."
            )

    return {
        "url": raw_url,
        "is_valid": True,
        "http_method": http_method.upper(),
        "result": overall_result,
        "risk_level": risk_level,
        "explanation": " ".join(explanations),
        "stages": stages,
        "suspicious_parameters": suspicious_params,
        "components": {
            "scheme": parsed.scheme or ("http" if not has_scheme else ""),
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path or "/",
            "query_string": parsed.query or "",
            "query_parameters": {k: [unquote_plus(v) for v in vs] for k, vs in query_params.items()},
            "fragment": parsed.fragment or ""
        },
        "path_analysis": path_detection,
        "parameter_analysis": param_analysis,
        "disclaimer": (
            "Static analysis tests submitted text against known attack signatures and ML models. "
            "It cannot verify backend server logic, authentication state, or database query assembly."
        )
    }
