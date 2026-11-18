"""
SQLITE PERSISTENT DATABASE MODULE FOR DETECTION HISTORY & TELEMETRY
===================================================================
Provides durable storage for scan events, telemetry, and overview metrics.
Eliminates temporary browser-only data dependency.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

DB_PATH = Path(__file__).resolve().parent / "detection_history.db"


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row access."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema and creates necessary indices."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                created_at REAL NOT NULL,
                input_type TEXT NOT NULL,
                input_preview TEXT NOT NULL,
                input_full TEXT NOT NULL,
                http_method TEXT,
                endpoint TEXT,
                result TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                stages_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                stage_details_json TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_records(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_result ON scan_records(result)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_records(input_type)")
        conn.commit()

        # Seed with initial diverse records if brand new table
        cur = conn.execute("SELECT COUNT(*) AS cnt FROM scan_records")
        count = cur.fetchone()["cnt"]
        if count == 0:
            seed_initial_records(conn)


def seed_initial_records(conn: sqlite3.Connection):
    """Inserts initial baseline historical scans for immediate academic presentation."""
    now = time.time()
    initial_records = [
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 3600)),
            now - 3600,
            "Authentication / User Request",
            "normal user login request",
            "normal user login request",
            "POST",
            "/api/v1/auth/login",
            "Safe",
            "None",
            json.dumps({"regex": False, "dfa": False, "cfg": False, "ml": False}),
            "No malicious pattern was detected by the configured detection methods.",
            json.dumps([]),
            json.dumps({})
        ),
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 2800)),
            now - 2800,
            "SQL Query / Injection Fragment",
            "admin' OR 1=1 --",
            "admin' OR 1=1 --",
            "POST",
            "/api/v1/users/search",
            "Malicious",
            "High",
            json.dumps({"regex": True, "dfa": True, "cfg": True, "ml": True}),
            "A SQL injection pattern was detected. The input contains a condition commonly used to manipulate a SQL query.",
            json.dumps([
                "Regex Rule [SQLI_TAUTOLOGY_OR]: SQL Tautology / Boolean Bypass (OR 1=1)",
                "Automaton [SQL Comment DFA]: Reached accepting state 'q_accept_dash'",
                "Grammar Syntax [SQL_TAUTOLOGY]: Injected boolean condition 'OR 1=1'"
            ]),
            json.dumps({})
        ),
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 2100)),
            now - 2100,
            "Numeric Identifier (Single/Multi-digit)",
            "7",
            "7",
            "GET",
            "/api/v1/products/7",
            "Safe",
            "None",
            json.dumps({"regex": False, "dfa": False, "cfg": False, "ml": False}),
            "No malicious pattern was detected by the configured detection methods.",
            json.dumps([]),
            json.dumps({})
        ),
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 1400)),
            now - 1400,
            "HTML / Cross-Site Script (XSS) Payload",
            "<script>alert(document.cookie)</script>",
            "<script>alert(document.cookie)</script>",
            "POST",
            "/api/v1/comments",
            "Malicious",
            "High",
            json.dumps({"regex": True, "dfa": True, "cfg": False, "ml": True}),
            "A Cross-Site Scripting (XSS) pattern was detected. The input contains executable script blocks designed to execute in a browser.",
            json.dumps([
                "Regex Rule [XSS_SCRIPT_TAG]: HTML Script Tag Injection",
                "Automaton [HTML Script Tag DFA]: Reached accepting state 'q_accept'"
            ]),
            json.dumps({})
        ),
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 700)),
            now - 700,
            "URL / API Endpoint",
            "https://api.example.com/v1/products?id=7&page=1",
            "https://api.example.com/v1/products?id=7&page=1",
            "GET",
            "/v1/products",
            "Safe",
            "None",
            json.dumps({"regex": False, "dfa": False, "cfg": False, "ml": False}),
            "No malicious SQLi, XSS, Path Traversal, or Command Injection patterns detected across query parameters.",
            json.dumps([]),
            json.dumps({})
        ),
        (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 120)),
            now - 120,
            "File System Path / Directory Traversal",
            "../../../../etc/passwd",
            "../../../../etc/passwd",
            "GET",
            "/api/v1/files/download",
            "Malicious",
            "High",
            json.dumps({"regex": True, "dfa": True, "cfg": False, "ml": False}),
            "A Path Traversal pattern was detected. The input contains directory escape sequences designed to access sensitive server files.",
            json.dumps([
                "Regex Rule [PATH_TRAVERSAL_DOTS]: Relative Directory Traversal",
                "Automaton [Path Traversal DFA]: Reached accepting state 'q_accept'"
            ]),
            json.dumps({})
        )
    ]

    conn.executemany("""
        INSERT INTO scan_records (
            timestamp, created_at, input_type, input_preview, input_full,
            http_method, endpoint, result, risk_level, stages_json,
            explanation, indicators_json, stage_details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, initial_records)
    conn.commit()


def add_scan_record(
    input_type: str,
    preview: str,
    full_text: str,
    result: str,
    risk_level: str,
    stages: Dict[str, bool],
    explanation: str,
    indicators: List[str],
    stage_details: Optional[Dict[str, Any]] = None,
    http_method: Optional[str] = None,
    endpoint: Optional[str] = None
) -> int:
    """Inserts a new scan record into SQLite and returns the inserted ID."""
    now = time.time()
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    stages_str = json.dumps(stages or {})
    ind_str = json.dumps(indicators or [])
    det_str = json.dumps(stage_details or {})

    with get_db_connection() as conn:
        cur = conn.execute("""
            INSERT INTO scan_records (
                timestamp, created_at, input_type, input_preview, input_full,
                http_method, endpoint, result, risk_level, stages_json,
                explanation, indicators_json, stage_details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, now, input_type or "Text", preview or "", full_text or "",
            http_method, endpoint, result or "Safe", risk_level or "None",
            stages_str, explanation or "", ind_str, det_str
        ))
        conn.commit()
        return cur.lastrowid


def get_scan_records(
    search: Optional[str] = None,
    verdict: Optional[str] = None,
    input_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """Retrieves paginated and filtered scan records from SQLite."""
    query = "SELECT * FROM scan_records WHERE 1=1"
    params = []

    if search:
        query += " AND (input_preview LIKE ? OR input_full LIKE ? OR explanation LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term])

    if verdict and verdict.lower() != "all":
        query += " AND LOWER(result) = LOWER(?)"
        params.append(verdict)

    if input_type and input_type.lower() != "all":
        query += " AND LOWER(input_type) LIKE LOWER(?)"
        params.append(f"%{input_type}%")

    count_query = query.replace("SELECT *", "SELECT COUNT(*) AS total")

    with get_db_connection() as conn:
        total_cur = conn.execute(count_query, params)
        total = total_cur.fetchone()["total"]

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()

        records = []
        for r in rows:
            records.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "created_at": r["created_at"],
                "input_type": r["input_type"],
                "preview": r["input_preview"],
                "input_full": r["input_full"],
                "http_method": r["http_method"],
                "endpoint": r["endpoint"],
                "result": r["result"],
                "risk_level": r["risk_level"],
                "stages": json.loads(r["stages_json"]) if r["stages_json"] else {},
                "explanation": r["explanation"],
                "indicators": json.loads(r["indicators_json"]) if r["indicators_json"] else []
            })

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": records
        }


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves complete details of an individual scan record."""
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scan_records WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "created_at": row["created_at"],
            "input_type": row["input_type"],
            "preview": row["input_preview"],
            "input_full": row["input_full"],
            "http_method": row["http_method"],
            "endpoint": row["endpoint"],
            "result": row["result"],
            "risk_level": row["risk_level"],
            "stages": json.loads(row["stages_json"]) if row["stages_json"] else {},
            "explanation": row["explanation"],
            "indicators": json.loads(row["indicators_json"]) if row["indicators_json"] else [],
            "stage_details": json.loads(row["stage_details_json"]) if row["stage_details_json"] else {}
        }


def delete_scan_record(scan_id: int) -> bool:
    """Deletes a single scan by ID."""
    with get_db_connection() as conn:
        cur = conn.execute("DELETE FROM scan_records WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0


def clear_all_scans():
    """Wipes all scan records from the database."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM scan_records")
        conn.commit()


def get_overview_statistics() -> Dict[str, Any]:
    """
    Computes real-time overview analytics:
    - Total inputs scanned
    - Safe inputs count
    - Malicious inputs count
    - Threat detection percentage
    - Detection method triggers (Regex, DFA, CFG, ML)
    - Recent 5 threats
    - Recent 8 scans
    """
    with get_db_connection() as conn:
        total = conn.execute("SELECT COUNT(*) as c FROM scan_records").fetchone()["c"]
        safe = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE LOWER(result) = 'safe'").fetchone()["c"]
        malicious = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE LOWER(result) = 'malicious'").fetchone()["c"]

        threat_pct = round((malicious / total * 100), 1) if total > 0 else 0.0

        # Method statistics
        regex_hits = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE stages_json LIKE '%\"regex\": true%'").fetchone()["c"]
        dfa_hits = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE stages_json LIKE '%\"dfa\": true%'").fetchone()["c"]
        cfg_hits = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE stages_json LIKE '%\"cfg\": true%'").fetchone()["c"]
        ml_hits = conn.execute("SELECT COUNT(*) as c FROM scan_records WHERE stages_json LIKE '%\"ml\": true%'").fetchone()["c"]

        # Recent threats
        threat_rows = conn.execute("""
            SELECT id, timestamp, input_type, input_preview, risk_level, stages_json, explanation
            FROM scan_records
            WHERE LOWER(result) = 'malicious'
            ORDER BY created_at DESC
            LIMIT 5
        """).fetchall()

        recent_threats = []
        for r in threat_rows:
            recent_threats.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "type": r["input_type"],
                "preview": r["input_preview"],
                "risk_level": r["risk_level"],
                "stages": json.loads(r["stages_json"]) if r["stages_json"] else {},
                "explanation": r["explanation"]
            })

        # Recent overall scans
        recent_rows = conn.execute("""
            SELECT id, timestamp, input_type, input_preview, result, risk_level, stages_json, explanation
            FROM scan_records
            ORDER BY created_at DESC
            LIMIT 8
        """).fetchall()

        recent_activity = []
        for r in recent_rows:
            recent_activity.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "type": r["input_type"],
                "preview": r["input_preview"],
                "result": r["result"],
                "risk_level": r["risk_level"],
                "stages": json.loads(r["stages_json"]) if r["stages_json"] else {},
                "explanation": r["explanation"]
            })

        return {
            "total_scanned": total,
            "safe_count": safe,
            "malicious_count": malicious,
            "threat_percentage": threat_pct,
            "method_breakdown": {
                "regex_triggers": regex_hits,
                "dfa_triggers": dfa_hits,
                "cfg_triggers": cfg_hits,
                "ml_triggers": ml_hits
            },
            "recent_threats": recent_threats,
            "recent_activity": recent_activity,
            "system_status": {
                "engine": "Online",
                "database": "SQLite (Persistent)",
                "regex_module": "Active",
                "dfa_module": "Active",
                "cfg_module": "Active",
                "ml_module": "Active (Calibrated)"
            }
        }


# Auto-initialize database on import
init_db()
