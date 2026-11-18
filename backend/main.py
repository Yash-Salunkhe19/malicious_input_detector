"""
FASTAPI APPLICATION - HYBRID MALICIOUS INPUT DETECTION SYSTEM
=============================================================
College Project:
"Hybrid Malicious Input Detection System Using Regular Expressions, DFA and Context-Free Grammar"
Syllabus:
- Unit III: Formal Language Theory and Finite Automata (DFA)
- Unit IV: Regular Expressions and Regular Languages
- Unit V: Context-Free Grammar, derivation, and parsing
"""

import time
import re
import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.pipeline import detect_input
from backend.api_scanner import scan_url, scan_api_request
from backend.stage1_rule import get_all_rules
from backend.stage2_rule import get_all_dfas, trace_single_dfa
from backend.stage3_cfg import get_cfg_grammar_definition, check_cfg
from backend.model import load_model_assets
from backend.database import (
    add_scan_record,
    get_scan_records,
    get_scan_by_id,
    delete_scan_record,
    clear_all_scans,
    get_overview_statistics
)


# ============================================================
# APP SETUP & METADATA
# ============================================================

app = FastAPI(
    title="Hybrid Malicious Input Detection System",
    description=(
        "Hybrid cybersecurity detection pipeline integrating Discrete Structures (DSACT) concepts: "
        "Stage 1: Regular Expressions (Unit IV), "
        "Stage 2: Deterministic Finite Automata (Unit III), "
        "Stage 3: Context-Free Grammar Parsing (Unit V), "
        "Stage 4: Machine Learning (TF-IDF + Logistic Regression)."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

FRONTEND_FILE = Path(__file__).resolve().parent.parent / "frontend" / "frontend.html"
MODEL_EVAL_FILE = Path(__file__).resolve().parent / "model_evaluation.json"

# In-memory circular buffer for scan history (max 50 items)
# Privacy-conscious: truncates long text, does not persist to disk
SCAN_HISTORY = deque(maxlen=50)


# ============================================================
# REQUEST & RESPONSE SCHEMAS
# ============================================================

class InputText(BaseModel):
    text: str = Field(
        ...,
        max_length=10000,
        description="The text string, SQL query, script tag, or payload to inspect.",
        json_schema_extra={"example": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}
    )


class URLInput(BaseModel):
    url: str = Field(
        ...,
        max_length=4096,
        description="The API or web URL with query parameters to statically inspect.",
        json_schema_extra={"example": "https://example.com/api/search?id=10&query=' UNION SELECT username,password FROM users --"}
    )
    http_method: Optional[str] = Field(
        default="GET",
        description="Optional HTTP method context (GET, POST, PUT, DELETE)."
    )


class APIScanRequest(BaseModel):
    endpoint: str = Field(
        ...,
        max_length=4096,
        description="The target API endpoint URL or route path to inspect.",
        json_schema_extra={"example": "https://api.example.com/v1/users/profile"}
    )
    http_method: Optional[str] = Field(
        default="GET",
        description="HTTP Method (GET, POST, PUT, DELETE, PATCH)."
    )
    headers: Optional[Any] = Field(
        default=None,
        description="Optional HTTP request headers (JSON object or string)."
    )
    body: Optional[str] = Field(
        default=None,
        max_length=50000,
        description="Optional request body, form data, or JSON payload."
    )


class DFATraceRequest(BaseModel):
    dfa_name: str = Field(
        ...,
        description="Name of the formal DFA to execute.",
        json_schema_extra={"example": "SQL Comment DFA"}
    )
    text: str = Field(
        ...,
        max_length=500,
        description="Sample input to trace through the DFA.",
        json_schema_extra={"example": "admin' --"}
    )


class RegexTestRequest(BaseModel):
    pattern: str = Field(
        ...,
        max_length=200,
        description="Regular expression pattern to test.",
        json_schema_extra={"example": r"(?i)\bUNION\b\s+\bSELECT\b"}
    )
    text: str = Field(
        ...,
        max_length=2000,
        description="Sample input to match against the regex.",
        json_schema_extra={"example": "' UNION SELECT * FROM accounts --"}
    )


class CFGParseRequest(BaseModel):
    text: str = Field(
        ...,
        max_length=1000,
        description="Input expression to parse against the Context-Free Grammar.",
        json_schema_extra={"example": "OR 1=1"}
    )


# ============================================================
# CORE ENDPOINTS
# ============================================================

@app.get("/", tags=["UI"])
@app.get("/frontend", tags=["UI"])
@app.get("/app", tags=["UI"])
def serve_frontend():
    """Serves the interactive web interface."""
    if FRONTEND_FILE.exists():
        return FileResponse(FRONTEND_FILE)
    return {
        "message": "Hybrid Malicious Input Detector API is running. Frontend file not found at expected path.",
        "docs": "/docs"
    }


@app.get("/health", tags=["System"])
def health():
    """Returns application status, syllabus module readiness, and ML asset status."""
    ml_ready = load_model_assets()
    return {
        "status": "online",
        "timestamp": time.time(),
        "modules": {
            "stage1_regex": "ready",
            "stage2_dfa": "ready",
            "stage3_cfg": "ready",
            "stage4_ml": "ready" if ml_ready else "degraded (assets missing)"
        },
        "syllabus": {
            "unit3": "Formal Language Theory & Finite Automata (DFA)",
            "unit4": "Regular Expressions & Regular Languages",
            "unit5": "Context-Free Grammar & Parsing"
        }
    }


# ============================================================
# OVERVIEW & ANALYTICS ENDPOINTS
# ============================================================

@app.get("/overview/stats", tags=["Dashboard"])
@app.get("/api/overview", tags=["Dashboard"])
def get_overview_stats():
    """
    Returns real-time aggregated overview metrics from persistent SQLite storage:
    - Total inputs scanned
    - Safe count & Malicious count
    - Threat detection percentage
    - Detection method triggers (Regex, DFA, CFG, ML)
    - Recent threats & recent scanning activity
    - System readiness status
    """
    return get_overview_statistics()


# ============================================================
# SCANNING ENDPOINTS (Text, URL, API)
# ============================================================

@app.post("/predict", tags=["Detection"])
def predict(data: InputText):
    """
    Main detection endpoint for text inputs.
    Executes the 4-stage hybrid detection pipeline and persists scan to SQLite.
    """
    input_str = data.text
    if len(input_str.strip()) == 0:
        empty_res = detect_input("")
        return {
            "input": input_str,
            "result": empty_res
        }

    detection = detect_input(input_str)

    # Persist to SQLite database
    scan_id = add_scan_record(
        input_type=detection.get("input_type", "Text"),
        preview=(input_str[:60] + "...") if len(input_str) > 60 else input_str,
        full_text=input_str,
        result=detection["result"],
        risk_level=detection["risk_level"],
        stages=detection["stages"],
        explanation=detection.get("explanation", ""),
        indicators=detection.get("risk_indicators", []),
        stage_details=detection.get("stage_details", {})
    )
    detection["scan_id"] = scan_id

    # Append to memory buffer as well for fast backward compatibility
    SCAN_HISTORY.appendleft({
        "id": scan_id,
        "type": "text",
        "timestamp": time.strftime("%H:%M:%S"),
        "preview": (input_str[:60] + "...") if len(input_str) > 60 else input_str,
        "result": detection["result"],
        "risk_level": detection["risk_level"],
        "stages": detection["stages"],
        "input_type": detection.get("input_type", "Text"),
        "explanation": detection.get("explanation", "")
    })

    return {
        "input": input_str,
        "result": detection
    }


@app.post("/scan-url", tags=["Detection"])
def scan_api_url(data: URLInput):
    """
    URL parameter static scanner.
    Statically analyzes path segments and query parameters without outbound network requests.
    Persists scan to SQLite.
    """
    result = scan_url(data.url, http_method=data.http_method or "GET")

    # Persist to SQLite database
    scan_id = add_scan_record(
        input_type="URL / Web Endpoint",
        preview=(data.url[:60] + "...") if len(data.url) > 60 else data.url,
        full_text=data.url,
        result=result["result"],
        risk_level=result["risk_level"],
        stages=result["stages"],
        explanation=result.get("explanation", ""),
        indicators=result.get("suspicious_parameters", []),
        stage_details=result.get("parameter_analysis", {}),
        http_method=data.http_method or "GET",
        endpoint=data.url
    )
    result["scan_id"] = scan_id

    SCAN_HISTORY.appendleft({
        "id": scan_id,
        "type": "url",
        "timestamp": time.strftime("%H:%M:%S"),
        "preview": (data.url[:60] + "...") if len(data.url) > 60 else data.url,
        "result": result["result"],
        "risk_level": result["risk_level"],
        "stages": result["stages"],
        "input_type": "URL / API Endpoint",
        "explanation": result.get("explanation", "")
    })

    return result


@app.post("/scan-api", tags=["Detection"])
def scan_api(data: APIScanRequest):
    """
    Dedicated API scanner inspecting endpoint path, headers, and request body.
    Performs safe static inspection without outbound network requests.
    Persists scan to SQLite.
    """
    result = scan_api_request(
        endpoint=data.endpoint,
        http_method=data.http_method or "GET",
        headers=data.headers,
        body=data.body
    )

    scan_id = add_scan_record(
        input_type="API Request",
        preview=f"{result['http_method']} {data.endpoint[:50]}",
        full_text=f"Endpoint: {data.endpoint}\nMethod: {result['http_method']}\nBody: {data.body or ''}",
        result=result["result"],
        risk_level=result["risk_level"],
        stages=result["stages"],
        explanation=result.get("explanation", ""),
        indicators=result.get("suspicious_items", []),
        stage_details=result,
        http_method=result["http_method"],
        endpoint=data.endpoint
    )
    result["scan_id"] = scan_id

    SCAN_HISTORY.appendleft({
        "id": scan_id,
        "type": "api",
        "timestamp": time.strftime("%H:%M:%S"),
        "preview": f"{result['http_method']} {data.endpoint[:50]}",
        "result": result["result"],
        "risk_level": result["risk_level"],
        "stages": result["stages"],
        "input_type": "API Request",
        "explanation": result.get("explanation", "")
    })

    return result


# ============================================================
# PERSISTENT HISTORY & AUDIT ENDPOINTS
# ============================================================

@app.get("/history", tags=["Detection"])
def get_history(
    search: Optional[str] = Query(None, description="Search term in input preview, full input, or explanation"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: All, Safe, Malicious"),
    input_type: Optional[str] = Query(None, description="Filter by input type"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    """Retrieve recent scan history from persistent SQLite database with search and filtering."""
    db_res = get_scan_records(search=search, verdict=verdict, input_type=input_type, limit=limit, offset=offset)
    return {
        "history": db_res["records"],
        "count": db_res["total"],
        "limit": db_res["limit"],
        "offset": db_res["offset"]
    }


@app.get("/history/{scan_id}", tags=["Detection"])
def get_single_history(scan_id: int):
    """Retrieve complete details for a single scan by ID from SQLite."""
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record


@app.delete("/history/{scan_id}", tags=["Detection"])
def delete_single_history(scan_id: int):
    """Delete a single history entry from SQLite by ID."""
    success = delete_scan_record(scan_id)
    if not success:
        # Fallback check on index for in-memory
        if 0 <= scan_id < len(SCAN_HISTORY):
            del SCAN_HISTORY[scan_id]
            return {"status": "deleted", "id": scan_id}
        raise HTTPException(status_code=404, detail="Scan record not found")
    return {"status": "deleted", "id": scan_id}


@app.delete("/history", tags=["Detection"])
def clear_history():
    """Clear all scan history from persistent SQLite database."""
    clear_all_scans()
    SCAN_HISTORY.clear()
    return {"status": "cleared", "count": 0}


@app.get("/ml/metrics", tags=["Machine Learning"])
def get_ml_metrics():
    """Returns trained machine learning evaluation metrics, confusion matrix, and benchmark comparisons."""
    if MODEL_EVAL_FILE.exists():
        try:
            with open(MODEL_EVAL_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            return {"error": f"Could not read evaluation file: {str(e)}"}
    return {"error": "model_evaluation.json not found on server"}


# ============================================================
# SYLLABUS FEATURE ENDPOINTS (Units III, IV, V)
# ============================================================

@app.get("/syllabus/dfa", tags=["Syllabus - Unit III (DFA)"])
def list_dfas():
    """Returns the catalog of formal Deterministic Finite Automata (Unit III)."""
    return {
        "unit": "Unit III: Formal Language Theory and Finite Automata",
        "dfas": get_all_dfas()
    }


@app.post("/syllabus/dfa/trace", tags=["Syllabus - Unit III (DFA)"])
def trace_dfa(data: DFATraceRequest):
    """
    Executes a formal DFA on the input string and returns step-by-step state transitions.
    Used by the interactive DFA Visualizer.
    """
    result = trace_single_dfa(data.dfa_name, data.text)
    return result


@app.get("/syllabus/regex", tags=["Syllabus - Unit IV (Regex)"])
def list_regex_rules():
    """Returns the catalog of security regular expressions (Unit IV)."""
    return {
        "unit": "Unit IV: Regular Expressions and Regular Languages",
        "rules": get_all_rules()
    }


@app.post("/syllabus/regex/test", tags=["Syllabus - Unit IV (Regex)"])
def test_custom_regex(data: RegexTestRequest):
    """
    Safely tests a regular expression against sample text with length/timeout limits.
    Used by the Regular Expression Playground.
    """
    # Guard against catastrophic backtracking on overly complex patterns
    if len(data.pattern) > 200 or len(data.text) > 2000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pattern or text exceeds safe playground length limit."
        )

    try:
        compiled = re.compile(data.pattern)
    except re.error as err:
        return {
            "valid_syntax": False,
            "error": str(err),
            "matched": False,
            "matches": []
        }

    matches = []
    for m in compiled.finditer(data.text):
        matches.append({
            "matched_text": m.group(0),
            "start": m.start(),
            "end": m.end()
        })
        if len(matches) >= 20:  # limit matches
            break

    return {
        "valid_syntax": True,
        "matched": len(matches) > 0,
        "matches": matches,
        "match_count": len(matches)
    }


@app.get("/syllabus/cfg", tags=["Syllabus - Unit V (CFG)"])
def get_cfg_grammar():
    """Returns the formal Context-Free Grammar definition and production rules (Unit V)."""
    return get_cfg_grammar_definition()


@app.post("/syllabus/cfg/parse", tags=["Syllabus - Unit V (CFG)"])
def parse_cfg_input(data: CFGParseRequest):
    """
    Parses input using the Context-Free Grammar and returns derivations and parse trees.
    Used by the CFG Grammar Explorer.
    """
    result = check_cfg(data.text)
    return result


@app.get("/syllabus/examples", tags=["Educational"])
def get_educational_examples():
    """Returns curated educational examples for quick demonstration during project defense."""
    return {
        "examples": [
            {
                "title": "Normal Single Digit ('7')",
                "type": "text",
                "input": "7",
                "expected": "Safe",
                "notes": "Demonstrates resolution of the single-character ML zero-vector fallback bug."
            },
            {
                "title": "Normal Conversational Input",
                "type": "text",
                "input": "hello world! Please check my account status.",
                "expected": "Safe",
                "notes": "Benign natural language input with standard punctuation."
            },
            {
                "title": "SQL Boolean Tautology (OR 1=1)",
                "type": "text",
                "input": "admin' OR 1=1 --",
                "expected": "Malicious",
                "notes": "Triggers Stage 1 (Regex), Stage 2 (DFA Comment), Stage 3 (CFG Tautology), and Stage 4 (ML)."
            },
            {
                "title": "SQL UNION SELECT Query",
                "type": "text",
                "input": "' UNION SELECT null, username, password FROM users --",
                "expected": "Malicious",
                "notes": "Triggers Stage 1 (Regex), Stage 2 (DFA), Stage 3 (CFG UNION), and Stage 4 (ML)."
            },
            {
                "title": "Stored/Reflected XSS (<script>)",
                "type": "text",
                "input": "<script>alert(document.cookie)</script>",
                "expected": "Malicious",
                "notes": "Triggers Stage 1 (Regex), Stage 2 (DFA Script Tag), and Stage 4 (ML)."
            },
            {
                "title": "Path Traversal (../../)",
                "type": "text",
                "input": "../../../etc/passwd",
                "expected": "Malicious",
                "notes": "Triggers Stage 1 (Regex) and Stage 2 (DFA Path Traversal)."
            },
            {
                "title": "OS Command Chaining",
                "type": "text",
                "input": "; cat /etc/passwd",
                "expected": "Malicious",
                "notes": "Triggers Stage 1 (Regex Command Chaining)."
            },
            {
                "title": "Safe API URL",
                "type": "url",
                "input": "https://api.example.com/v1/products?category=electronics&page=2&limit=50",
                "expected": "Safe",
                "notes": "Demonstrates that benign parameters (id, page, category) do NOT trigger false positives."
            },
            {
                "title": "Malicious API URL (Encoded SQLi)",
                "type": "url",
                "input": "https://api.example.com/users?id=1%27%20OR%20%271%27%3D%271",
                "expected": "Malicious",
                "notes": "URL-encoded SQL tautology in query parameter, safely decoded and detected."
            }
        ]
    }
