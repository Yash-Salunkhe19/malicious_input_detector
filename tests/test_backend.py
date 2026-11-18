"""
AUTOMATED TEST SUITE FOR HYBRID MALICIOUS INPUT DETECTOR
========================================================
Covers:
1. Normal text & numeric-only inputs (including '7', '1', '47209')
2. SQL injection examples (UNION SELECT, OR 1=1, comments)
3. Cross-Site Scripting (XSS) examples (<script>, event handlers)
4. Path traversal examples (../../etc/passwd)
5. Command injection examples (; cat /etc/passwd)
6. URL scanning (clean URLs, encoded attacks, malformed URLs)
7. DFA transition tracing and accepting state verification
8. CFG parsing, derivation logging, and limitations
9. API response schemas and health checks
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.stage1_rule import rule_based_detection
from backend.stage2_rule import DFA_SQL_COMMENT, DFA_SCRIPT_TAG, DFA_PATH_TRAVERSAL, DFA_SQL_OR, check_dfa
from backend.stage3_cfg import tokenize, check_cfg
from backend.pipeline import detect_input
from backend.api_scanner import scan_url

client = TestClient(app)


# ============================================================
# 1. HEALTH & ENDPOINT SCHEMA TESTS
# ============================================================

def test_health_check():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["modules"]["stage1_regex"] == "ready"
    assert data["modules"]["stage2_dfa"] == "ready"
    assert data["modules"]["stage3_cfg"] == "ready"
    assert data["modules"]["stage4_ml"] == "ready"


def test_empty_predict():
    res = client.post("/predict", json={"text": ""})
    assert res.status_code == 200
    data = res.json()
    assert data["result"]["result"] == "Safe"


def test_syllabus_endpoints():
    r_dfa = client.get("/syllabus/dfa")
    assert r_dfa.status_code == 200
    assert len(r_dfa.json()["dfas"]) >= 4

    r_reg = client.get("/syllabus/regex")
    assert r_reg.status_code == 200
    assert len(r_reg.json()["rules"]) >= 10

    r_cfg = client.get("/syllabus/cfg")
    assert r_cfg.status_code == 200
    assert r_cfg.json()["start_symbol"] == "S"

    r_ex = client.get("/syllabus/examples")
    assert r_ex.status_code == 200
    assert len(r_ex.json()["examples"]) >= 5


# ============================================================
# 2. NUMERIC & BENIGN TEXT (NO FALSE POSITIVES)
# ============================================================

@pytest.mark.parametrize("text", [
    "7",
    "1",
    "47209",
    "hello world",
    "normal user login request",
    "please view my account profile",
    "search query for laptops and phones",
])
def test_normal_inputs_classified_safe(text):
    res = detect_input(text)
    assert res["result"] == "Safe", f"Expected Safe for {text!r}, got: {res}"
    assert res["risk_level"] == "None"


# ============================================================
# 3. SQL INJECTION DETECTION (TRUE POSITIVES)
# ============================================================

@pytest.mark.parametrize("payload", [
    "admin' OR 1=1 --",
    "' UNION SELECT null, username, password FROM users --",
    "' OR '1'='1",
    "1; DROP TABLE users; --",
    "1' AND 1=1 --",
    "' OR SLEEP(5) --"
])
def test_sqli_detected_malicious(payload):
    res = detect_input(payload)
    assert res["result"] == "Malicious", f"Expected Malicious for {payload!r}"
    assert res["risk_level"] == "High"
    assert res["stages"]["regex"] or res["stages"]["dfa"] or res["stages"]["cfg"]


# ============================================================
# 4. XSS DETECTION (TRUE POSITIVES)
# ============================================================

@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:alert('XSS')",
    "<iframe src='http://attacker.com'></iframe>"
])
def test_xss_detected_malicious(payload):
    res = detect_input(payload)
    assert res["result"] == "Malicious", f"Expected Malicious for {payload!r}"
    assert res["stages"]["regex"] or res["stages"]["dfa"]


# ============================================================
# 5. PATH TRAVERSAL & COMMAND INJECTION
# ============================================================

@pytest.mark.parametrize("payload", [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "/etc/shadow",
    "; cat /etc/passwd",
    "| whoami",
    "&& dir"
])
def test_traversal_and_command_injection(payload):
    res = detect_input(payload)
    assert res["result"] == "Malicious", f"Expected Malicious for {payload!r}"


# ============================================================
# 6. DFA TRANSITION VERIFICATION (UNIT III)
# ============================================================

def test_dfa_sql_comment():
    res_accept = DFA_SQL_COMMENT.scan("SELECT * FROM users -- comment")
    assert res_accept["accepted"] is True
    assert res_accept["final_state"] in DFA_SQL_COMMENT.accept_states

    res_reject = DFA_SQL_COMMENT.scan("normal text without comments")
    assert res_reject["accepted"] is False


def test_dfa_script_tag():
    res_accept = DFA_SCRIPT_TAG.scan("<div><script>alert(1)</script></div>")
    assert res_accept["accepted"] is True

    res_reject = DFA_SCRIPT_TAG.scan("plain description text")
    assert res_reject["accepted"] is False


def test_dfa_path_traversal():
    res_accept = DFA_PATH_TRAVERSAL.scan("download?file=../../secret.txt")
    assert res_accept["accepted"] is True

    res_reject = DFA_PATH_TRAVERSAL.scan("download?file=document.pdf")
    assert res_reject["accepted"] is False


def test_dfa_trace_endpoint():
    res = client.post("/syllabus/dfa/trace", json={
        "dfa_name": "SQL Comment DFA",
        "text": "test --"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["accepted"] is True
    assert len(data["trace_summary"]) > 0


# ============================================================
# 7. CONTEXT-FREE GRAMMAR PARSER (UNIT V)
# ============================================================

def test_cfg_tautology_parsing():
    res = check_cfg("OR 1=1")
    assert res["is_malicious"] is True
    assert len(res["structures"]) > 0
    assert res["structures"][0]["type"] == "SQL_TAUTOLOGY"
    assert len(res["derivations"]) > 0


def test_cfg_union_parsing():
    res = check_cfg("UNION SELECT * FROM users")
    assert res["is_malicious"] is True
    assert any(s["type"] == "SQL_UNION_INJECTION" for s in res["structures"])


def test_cfg_benign_rejected():
    res = check_cfg("simple text query without sql keywords")
    assert res["is_malicious"] is False


# ============================================================
# 8. URL AND API SCANNER TESTS
# ============================================================

def test_safe_url_scanning():
    url = "https://example.com/api/v1/products?id=7&category=books&page=1"
    res = scan_url(url)
    assert res["result"] == "Safe"
    assert res["risk_level"] == "None"
    assert len(res["suspicious_parameters"]) == 0
    assert res["components"]["hostname"] == "example.com"


def test_malicious_url_encoded_sqli():
    url = "https://example.com/search?q=%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users%20--"
    res = scan_url(url)
    assert res["result"] == "Malicious"
    assert res["risk_level"] == "High"
    assert "q" in res["suspicious_parameters"]


def test_malicious_url_path_traversal():
    url = "https://example.com/files/../../../../etc/passwd"
    res = scan_url(url)
    assert res["result"] == "Malicious"


def test_malformed_url_handled_safely():
    res = scan_url("://invalid-url-without-proper-format")
    assert res["is_valid"] in (True, False) # Does not raise unhandled exception


# ============================================================
# 9. EXPLAINABLE RESULTS & PROMPT SPECIFICATION VERIFICATION
# ============================================================

def test_explainable_detection_structure_benign():
    res = detect_input("normal user login request")
    assert res["result"] == "Safe"
    assert "No malicious pattern was detected" in res["explanation"]
    assert res["input_type"] == "Authentication / User Request"
    assert len(res["risk_indicators"]) == 0
    assert len(res["rule_by_rule_analysis"]) == 4
    assert res["decision_breakdown"]["primary_cause"].startswith("All stages cleared")
    assert "Logical OR" in res["decision_breakdown"]["combination_rule"]


def test_explainable_detection_structure_malicious():
    res = detect_input("' OR 1=1 --")
    assert res["result"] == "Malicious"
    assert "SQL injection pattern was detected" in res["explanation"]
    assert res["input_type"] == "SQL Query / Injection Fragment"
    assert len(res["risk_indicators"]) > 0
    assert any(c["status"] == "Triggered" for c in res["rule_by_rule_analysis"])
    assert "Regex / Rule Matching" in res["decision_breakdown"]["flagged_stages"]


def test_ml_metrics_endpoint():
    res = client.get("/ml/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "selected_metrics" in data
    assert data["selected_metrics"]["accuracy"] > 0.90
    assert data["selected_metrics"]["false_positive_rate"] < 0.05


def test_history_clear_and_delete_endpoints():
    # Insert a scan
    client.post("/predict", json={"text": "test_history_item"})
    
    # Check history has items
    res = client.get("/history")
    assert res.status_code == 200
    initial_count = res.json()["count"]
    assert initial_count > 0

    # Delete index 0
    res_del = client.delete("/history/0")
    assert res_del.status_code == 200

    # Clear all history
    res_clear = client.delete("/history")
    assert res_clear.status_code == 200
    assert res_clear.json()["count"] == 0


def test_overview_stats_endpoint():
    # Insert at least one scan so stats compute
    client.post("/predict", json={"text": "hello overview world"})
    res = client.get("/overview/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_scanned" in data
    assert "safe_count" in data
    assert "malicious_count" in data
    assert "method_breakdown" in data
    assert "system_status" in data


def test_scan_api_endpoint_safe():
    payload = {
        "endpoint": "https://api.example.com/v1/orders",
        "http_method": "POST",
        "headers": {"Authorization": "Bearer token123", "Content-Type": "application/json"},
        "body": '{"order_id": 1042, "item": "laptop"}'
    }
    res = client.post("/scan-api", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "Safe"
    assert data["risk_level"] == "None"


def test_scan_api_endpoint_malicious_body():
    payload = {
        "endpoint": "https://api.example.com/v1/login",
        "http_method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": '{"username": "admin\' OR 1=1 --", "password": "123"}'
    }
    res = client.post("/scan-api", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["result"] == "Malicious"
    assert data["risk_level"] == "High"
    assert any("Body Field: username" in item for item in data["suspicious_items"])


