"""
MAIN DETECTION PIPELINE & EXPLAINABILITY ENGINE
===============================================
Coordinates the 4-stage hybrid detection architecture:
    Stage 1 -> Regular Expressions (Unit IV)
    Stage 2 -> Deterministic Finite Automata (Unit III)
    Stage 3 -> Context-Free Grammar (Unit V)
    Stage 4 -> Machine Learning (Logistic Regression with TF-IDF)

Decision Logic:
1. Deterministic Rule Stages (Regex, DFA, CFG):
   - High precision, explainable syntax violations.
   - Evaluated under a Logical OR policy: If ANY deterministic stage matches,
     the input is verified MALICIOUS.
2. Machine Learning Stage (Stage 4):
   - Statistical generalization on text and token n-grams.
   - Evaluated as a secondary check if deterministic stages pass.
   - If P(Malicious) > 0.50, flags as statistical anomaly.
3. If no stage flags the input:
   - Returns SAFE with explicit statement of coverage and static limitations.
"""

from typing import Dict, Any, List

from backend.stage1_rule import rule_based_detection
from backend.stage2_rule import check_dfa
from backend.stage3_cfg import check_cfg
from backend.model import predict_text


def determine_input_type(
    text: str,
    regex_res: Dict[str, Any],
    dfa_res: Dict[str, Any],
    cfg_res: Dict[str, Any]
) -> str:
    """
    Infers the functional type of the input string based on lexical and structural features.
    """
    trimmed = (text or "").strip()
    if not trimmed:
        return "Empty Input"

    if trimmed.isdigit():
        return "Numeric Identifier (Single/Multi-digit)"

    if trimmed.startswith(("http://", "https://", "ftp://", "ws://", "wss://")) or ("?" in trimmed and "=" in trimmed and "/" in trimmed):
        return "API Endpoint / URL"

    matched_cats = set()
    for m in regex_res.get("matches", []):
        matched_cats.add(m.get("category"))
    for m in dfa_res.get("matches", []):
        matched_cats.add(m.get("category"))
    if cfg_res.get("is_malicious", False):
        matched_cats.add("SQL Injection")

    if "SQL Injection" in matched_cats:
        return "SQL Query / Injection Fragment"
    if "Cross-Site Scripting (XSS)" in matched_cats or "<script" in trimmed.lower() or "onerror=" in trimmed.lower():
        return "HTML / Cross-Site Script (XSS) Payload"
    if "Path Traversal" in matched_cats or "../" in trimmed or "..\\" in trimmed:
        return "File System Path / Directory Traversal"
    if "Command Injection" in matched_cats or ((";" in trimmed or "|" in trimmed or "&&" in trimmed) and any(cmd in trimmed.lower() for cmd in ["cat", "ls", "whoami", "id", "dir", "pwd"])):
        return "Operating System Command / Chained Script"

    lower = trimmed.lower()
    if any(k in lower for k in ["login", "user", "password", "auth", "signin", "account", "token", "session"]):
        return "Authentication / User Request"
    if any(k in lower for k in ["select", "insert", "update", "delete", "drop", "union", "table", "from", "where"]):
        return "SQL Database Statement"
    if any(k in lower for k in ["http", "api", "v1", "v2", "json", "endpoint"]):
        return "API / Web Parameter String"

    return "Plain Text / Benign Input"


def extract_risk_indicators(
    regex_res: Dict[str, Any],
    dfa_res: Dict[str, Any],
    cfg_res: Dict[str, Any],
    ml_res: Dict[str, Any]
) -> List[str]:
    """
    Collects specific, observable risk indicators detected across the pipeline stages.
    """
    indicators: List[str] = []

    for m in regex_res.get("matches", []):
        indicators.append(f"Regex Rule [{m.get('rule_id')}]: {m.get('rule_name')}")

    for m in dfa_res.get("matches", []):
        indicators.append(f"Automaton [{m.get('dfa_name')}]: Reached accepting state '{m.get('final_state')}'")

    for s in cfg_res.get("structures", []):
        indicators.append(f"Grammar Syntax [{s.get('type')}]: {s.get('pattern')}")

    if ml_res.get("is_malicious"):
        prob = ml_res.get("malicious_probability", 0.0)
        prob_str = f"{prob * 100:.1f}%" if prob is not None else "High"
        indicators.append(f"Machine Learning: Statistical Anomaly Score (P(Malicious) = {prob_str})")

    # Deduplicate while maintaining sequence
    seen = set()
    deduped = []
    for item in indicators:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def detect_input(text: str) -> Dict[str, Any]:
    """
    Run the full 4-stage hybrid malicious input detector on the provided text.
    Returns complete structured detection telemetry and explainability data.
    """
    if text is None:
        text = ""

    # ========================================================
    # STAGE 1 - REGEX
    # ========================================================
    stage1_res = rule_based_detection(text)
    regex_flag = bool(stage1_res.get("matched", False))

    # ========================================================
    # STAGE 2 - DFA
    # ========================================================
    stage2_res = check_dfa(text)
    dfa_flag = bool(stage2_res.get("matched", False))

    # ========================================================
    # STAGE 3 - CFG
    # ========================================================
    stage3_res = check_cfg(text)
    cfg_flag = bool(stage3_res.get("matched", False))

    # ========================================================
    # STAGE 4 - MACHINE LEARNING
    # ========================================================
    stage4_res = predict_text(text)
    ml_flag = bool(stage4_res.get("is_malicious", False))
    ml_prob = stage4_res.get("malicious_probability", 0.0)

    # ========================================================
    # HYBRID DECISION LOGIC
    # ========================================================
    deterministic_match = regex_flag or dfa_flag or cfg_flag
    is_malicious = deterministic_match or ml_flag

    # Determine input type
    input_type = determine_input_type(text, stage1_res, stage2_res, stage3_res)

    # Risk indicators
    risk_indicators = extract_risk_indicators(stage1_res, stage2_res, stage3_res, stage4_res)

    # Flagged / Unflagged breakdown
    flagged_stages = []
    unflagged_stages = []
    if regex_flag:
        flagged_stages.append("Regex / Rule Matching")
    else:
        unflagged_stages.append("Regex / Rule Matching")

    if dfa_flag:
        flagged_stages.append("DFA Analysis")
    else:
        unflagged_stages.append("DFA Analysis")

    if cfg_flag:
        flagged_stages.append("Grammar Analysis")
    else:
        unflagged_stages.append("Grammar Analysis")

    if ml_flag:
        flagged_stages.append("Machine Learning")
    else:
        unflagged_stages.append("Machine Learning")

    # Plain English Explanations
    short_explanation = ""
    detailed_reasons = []

    if regex_flag:
        rule_names = [m["rule_name"] for m in stage1_res.get("matches", [])]
        detailed_reasons.append(f"Regex: Matched signature(s): {', '.join(rule_names[:3])}.")

    if dfa_flag:
        dfa_names = [m["dfa_name"] for m in stage2_res.get("matches", [])]
        detailed_reasons.append(f"DFA: Accepted by finite automaton: {', '.join(dfa_names)}.")

    if cfg_flag:
        detailed_reasons.append("CFG: Parser derived unauthorized SQL injection grammar structure.")

    if ml_flag:
        prob_pct = f"{ml_prob * 100:.1f}%" if ml_prob is not None else "High"
        detailed_reasons.append(f"ML: Statistical anomaly with {prob_pct} malicious probability.")

    if is_malicious:
        final_result = "Malicious"
        risk_level = "High" if deterministic_match else "Medium"
        finding_type = "Deterministic Rule Match" if deterministic_match else "ML Statistical Finding"

        # Generate clear plain English explanation
        if "SQL" in input_type or cfg_flag or any("SQL" in r for r in detailed_reasons):
            short_explanation = "A SQL injection pattern was detected. The input contains a condition, union projection, or comment marker commonly used to manipulate a SQL query."
        elif "HTML" in input_type or any("Script" in r or "XSS" in r for r in detailed_reasons):
            short_explanation = "A Cross-Site Scripting (XSS) pattern was detected. The input contains executable script blocks or event handlers designed to execute in a victim browser."
        elif "Path" in input_type or any("Path" in r for r in detailed_reasons):
            short_explanation = "A Path Traversal pattern was detected. The input contains directory escape sequences (e.g. '../') designed to access unauthorized files on the server."
        elif "Command" in input_type or any("Command" in r for r in detailed_reasons):
            short_explanation = "An OS Command Injection pattern was detected. The input attempts to chain shell control operators with system administration utilities."
        else:
            short_explanation = f"Input exhibited significant statistical similarity to known malicious attack payloads (P(Malicious) = {ml_prob * 100:.1f}%)."
    else:
        final_result = "Safe"
        risk_level = "None"
        finding_type = "None"
        short_explanation = "No malicious pattern was detected by the configured detection methods."

    # Rule-by-rule explainability cards
    # 1. Regex
    if regex_flag:
        r_matches = stage1_res.get("matches", [])
        r_names = [m.get("rule_name", m.get("rule_id", "Signature")) for m in r_matches]
        r_status = "Triggered"
        r_observed = f"Matched {len(r_matches)} rule(s): {', '.join(r_names)}."
        r_contribution = "Provides deterministic evidence of a known exploit signature. Contributes directly to the MALICIOUS classification."
    else:
        r_status = "Passed"
        r_observed = "No configured malicious regular expression pattern matched the input string."
        r_contribution = "Input passed all pre-compiled attack signatures. (Note: Signature matching checks known patterns and does not guarantee the absence of zero-day exploits.)"

    # 2. DFA
    if dfa_flag:
        d_matches = stage2_res.get("matches", [])
        d_names = [f"{m['dfa_name']} (accept state '{m['final_state']}')" for m in d_matches]
        d_status = "Triggered"
        d_observed = f"Accepted by automaton: {', '.join(d_names)}."
        d_contribution = "Formally proves language membership w ∈ L(M) in an attack sublanguage. Contributes directly to the MALICIOUS classification."
    else:
        d_status = "Passed"
        d_observed = "All active DFAs (Comment, Script Tag, Path Traversal, OR Tautology) completed in rejecting / non-accepting states."
        d_contribution = "Input does not contain target deterministic sequence fragments recognized by the automata."

    # 3. CFG
    if cfg_flag:
        cfg_structs = [s.get("type", "SQL Syntax") for s in stage3_res.get("structures", [])]
        c_status = "Triggered"
        c_observed = f"Recursive descent parser successfully derived unauthorized SQL structures: {', '.join(cfg_structs)}."
        c_contribution = "Syntactically proves structural query manipulation (e.g. injected tautology or UNION clause) beyond simple keyword matching."
    else:
        c_status = "Passed"
        c_observed = "Parser found no matching attack productions in the Context-Free Grammar."
        c_contribution = "Input does not derive dangerous query structures according to the documented CFG."

    # 4. ML
    ml_status = "Malicious" if ml_flag else "Safe"
    prob_val = stage4_res.get("malicious_probability", 0.0)
    prob_pct = f"{prob_val * 100:.1f}%" if prob_val is not None else "N/A"
    if ml_flag:
        m_observed = f"Model predicted Malicious with {prob_pct} statistical probability."
        m_contribution = "Input vocabulary has high statistical similarity to malicious payloads in the training dataset. (Note: ML predictions can produce false positives; evaluated alongside rules.)"
    else:
        safe_pct = f"{(1.0 - (prob_val or 0.0)) * 100:.1f}%"
        m_observed = f"Model predicted Safe with {safe_pct} normal confidence (P(Malicious) = {prob_pct})."
        m_contribution = "Vocabulary and n-gram distribution match benign application inputs in the training dataset."

    rule_by_rule_analysis = [
        {
            "concept": "Regex / Rule Matching",
            "status": r_status,
            "checks": "Evaluates input against compiled regular expressions defining known attack languages (SQLi, XSS, Path Traversal, OS Command Chaining).",
            "observed": r_observed,
            "rule_evidence": stage1_res.get("matches", []),
            "contribution": r_contribution
        },
        {
            "concept": "DFA Analysis",
            "status": d_status,
            "checks": "Processes input characters through formal deterministic finite state machines (Line Comments, Script Tags, Directory Traversal, OR Tautologies).",
            "observed": d_observed,
            "rule_evidence": stage2_res.get("matches", []),
            "contribution": d_contribution
        },
        {
            "concept": "Grammar Analysis",
            "status": c_status,
            "checks": "Uses Context-Free Grammar productions to derive structured SQL expressions (tautologies, UNION projections, boolean conditions).",
            "observed": c_observed,
            "rule_evidence": stage3_res.get("structures", []),
            "contribution": c_contribution
        },
        {
            "concept": "Machine Learning",
            "status": ml_status,
            "checks": "Extracts TF-IDF word and character n-grams and evaluates them using a calibrated Logistic Regression classifier.",
            "observed": m_observed,
            "rule_evidence": stage4_res,
            "contribution": m_contribution
        }
    ]

    # Primary cause of decision
    if deterministic_match:
        det_causes = []
        if regex_flag: det_causes.append("Regex Signatures")
        if dfa_flag: det_causes.append("Finite Automata")
        if cfg_flag: det_causes.append("Context-Free Grammar")
        primary_cause = f"Triggered by deterministic rules in: {', '.join(det_causes)}."
    elif ml_flag:
        primary_cause = f"Triggered by Machine Learning statistical anomaly (P(Malicious) = {prob_pct} > 50.0%)."
    else:
        primary_cause = "All stages cleared the input. No configured rule or statistical anomaly was detected."

    decision_breakdown = {
        "policy": "Deterministic Priority (Logical OR across Regex, DFA, CFG) with Machine Learning Secondary Threat Corroboration",
        "flagged_stages": flagged_stages,
        "unflagged_stages": unflagged_stages,
        "primary_cause": primary_cause,
        "combination_rule": (
            "Logical OR on deterministic stages (Regex, DFA, CFG): if ANY deterministic stage triggers, "
            "the verdict is immediately MALICIOUS. If all deterministic stages pass, the Machine Learning "
            "classifier is evaluated as a secondary check; if ML malicious probability exceeds 50%, "
            "the input is classified MALICIOUS, otherwise SAFE."
        )
    }

    return {
        "result": final_result,
        "risk_level": risk_level,
        "finding_type": finding_type,
        "explanation": short_explanation,
        "input_type": input_type,
        "risk_indicators": risk_indicators,
        "reasons": detailed_reasons,
        "rule_by_rule_analysis": rule_by_rule_analysis,
        "decision_breakdown": decision_breakdown,
        # Backward-compatible 4-stage boolean mapping:
        "stages": {
            "regex": regex_flag,
            "dfa": dfa_flag,
            "cfg": cfg_flag,
            "ml": ml_flag
        },
        # Comprehensive stage telemetry:
        "stage_details": {
            "regex": stage1_res,
            "dfa": stage2_res,
            "cfg": stage3_res,
            "ml": stage4_res
        }
    }
