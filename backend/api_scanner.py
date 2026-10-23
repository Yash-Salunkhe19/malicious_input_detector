from urllib.parse import urlparse, parse_qs, unquote

from backend.pipeline import detect_input


def scan_url(url: str):
    raw_url = (url or "").strip()

    if not raw_url:
        return {
            "url": url,
            "result": "Invalid URL",
            "stages": {
                "regex": False,
                "dfa": False,
                "cfg": False,
                "ml": False
            },
            "parameters": {}
        }

    # Normalize protocol if missing so urlparse extracts host/path/query correctly
    if not raw_url.startswith(("http://", "https://")):
        parsed = urlparse("http://" + raw_url)
    else:
        parsed = urlparse(raw_url)

    stages = {
        "regex": False,
        "dfa": False,
        "cfg": False,
        "ml": False
    }

    results = {}
    malicious_found = False

    def merge_stages(detection_stages):
        if isinstance(detection_stages, dict):
            for stage_name, triggered in detection_stages.items():
                if triggered:
                    stages[stage_name] = True

    # 1. Check decoded path
    decoded_path = unquote(parsed.path or "").strip("/")
    if decoded_path:
        path_detection = detect_input(decoded_path)
        if path_detection.get("result") == "Malicious":
            malicious_found = True
            merge_stages(path_detection.get("stages", {}))

        results["__path__"] = [{
            "value": decoded_path,
            "result": path_detection
        }]

    # 2. Check query parameters
    query_parameters = parse_qs(parsed.query)

    for parameter, values in query_parameters.items():
        parameter_results = []
        for value in values:
            decoded_value = unquote(value)
            detection = detect_input(decoded_value)

            if detection.get("result") == "Malicious":
                malicious_found = True
                merge_stages(detection.get("stages", {}))

            parameter_results.append({
                "value": decoded_value,
                "result": detection
            })

        results[parameter] = parameter_results

    # 3. If query parameters were present or path checked, also check the whole raw string as fallback
    full_detection = detect_input(raw_url)
    if full_detection.get("result") == "Malicious":
        malicious_found = True
        merge_stages(full_detection.get("stages", {}))

    overall_result = "Malicious" if malicious_found else "Safe"

    return {
        "url": url,
        "result": overall_result,
        "stages": stages,
        "parameters": results
    }
