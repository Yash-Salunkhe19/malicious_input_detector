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

import json
from urllib.parse import urlsplit, parse_qs, unquote_plus
from typing import Dict, Any, List, Optional

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


def scan_api_request(
    endpoint: str,
    http_method: str = "GET",
    headers: Optional[Any] = None,
    body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Statically analyzes an API request specification (endpoint, HTTP method, headers, and request body)
    for malicious injections without transmitting outbound requests.
    """
    clean_endpoint = (endpoint or "").strip()
    clean_method = (http_method or "GET").upper().strip()

    # Step 1: Scan the endpoint URL and path/query params
    endpoint_res = scan_url(clean_endpoint, http_method=clean_method)

    stages = {"regex": False, "dfa": False, "cfg": False, "ml": False}
    for k in ("regex", "dfa", "cfg", "ml"):
        if endpoint_res["stages"].get(k, False):
            stages[k] = True

    explanations: List[str] = []
    suspicious_items: List[str] = []

    if endpoint_res["result"] == "Malicious":
        explanations.append(f"Endpoint URL: {endpoint_res.get('explanation')}")
        suspicious_items.extend(endpoint_res.get("suspicious_parameters", []))

    # Step 2: Scan Headers (if provided)
    header_findings: Dict[str, Any] = {}
    parsed_headers: Dict[str, str] = {}
    if headers:
        if isinstance(headers, dict):
            parsed_headers = {str(k): str(v) for k, v in headers.items()}
        elif isinstance(headers, str):
            try:
                loaded = json.loads(headers)
                if isinstance(loaded, dict):
                    parsed_headers = {str(k): str(v) for k, v in loaded.items()}
            except Exception:
                for line in headers.strip().splitlines():
                    if ":" in line:
                        hk, hv = line.split(":", 1)
                        parsed_headers[hk.strip()] = hv.strip()

        for hk, hv in parsed_headers.items():
            h_det = detect_input(hv)
            if h_det.get("result") == "Malicious":
                for k in ("regex", "dfa", "cfg", "ml"):
                    if h_det["stages"].get(k, False):
                        stages[k] = True
                suspicious_items.append(f"Header: {hk}")
                explanations.append(f"Request Header '{hk}' contains malicious payload ({h_det.get('finding_type')}): {h_det.get('explanation')}")
            header_findings[hk] = {
                "value": hv,
                "result": h_det.get("result"),
                "risk_level": h_det.get("risk_level")
            }

    # Step 3: Scan Request Body (if provided)
    body_findings: List[Dict[str, Any]] = []
    clean_body = (body or "").strip()
    if clean_body:
        # Check if JSON
        is_json = False
        try:
            body_json = json.loads(clean_body)
            is_json = True
            def inspect_json_recursive(obj, prefix=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        new_prefix = f"{prefix}.{k}" if prefix else k
                        inspect_json_recursive(v, new_prefix)
                elif isinstance(obj, list):
                    for idx, item in enumerate(obj):
                        inspect_json_recursive(item, f"{prefix}[{idx}]")
                elif isinstance(obj, str):
                    det = detect_input(obj)
                    if det.get("result") == "Malicious":
                        for k in ("regex", "dfa", "cfg", "ml"):
                            if det["stages"].get(k, False):
                                stages[k] = True
                        suspicious_items.append(f"Body Field: {prefix}")
                        explanations.append(f"JSON field '{prefix}' contains malicious payload: {det.get('explanation')}")
                    body_findings.append({
                        "field": prefix,
                        "value": obj[:80] + ("..." if len(obj) > 80 else ""),
                        "result": det.get("result"),
                        "risk_level": det.get("risk_level")
                    })

            inspect_json_recursive(body_json)
        except Exception:
            pass

        # If not structured or raw text scan
        if not is_json:
            raw_det = detect_input(clean_body)
            if raw_det.get("result") == "Malicious":
                for k in ("regex", "dfa", "cfg", "ml"):
                    if raw_det["stages"].get(k, False):
                        stages[k] = True
                suspicious_items.append("Raw Request Body")
                explanations.append(f"Raw body payload is malicious: {raw_det.get('explanation')}")
            body_findings.append({
                "field": "raw_body",
                "value": clean_body[:80] + ("..." if len(clean_body) > 80 else ""),
                "result": raw_det.get("result"),
                "risk_level": raw_det.get("risk_level")
            })

    is_malicious = any(stages.values()) or (endpoint_res.get("result") == "Malicious")
    final_verdict = "Malicious" if is_malicious else "Safe"
    risk_level = "High" if any(stages[s] for s in ("regex", "dfa", "cfg")) else ("Medium" if stages["ml"] else "None")

    if not explanations:
        explanations.append(f"API request validated clean across endpoint, {len(parsed_headers)} header(s), and body payloads.")

    return {
        "endpoint": clean_endpoint,
        "http_method": clean_method,
        "result": final_verdict,
        "risk_level": risk_level,
        "explanation": " ".join(explanations),
        "stages": stages,
        "suspicious_items": suspicious_items,
        "endpoint_analysis": endpoint_res,
        "header_analysis": header_findings,
        "body_analysis": body_findings,
        "disclaimer": "Static inspection only. No outbound network requests were dispatched."
    }

