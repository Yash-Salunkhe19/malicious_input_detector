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
   - If any deterministic stage matches, input is verified MALICIOUS.
2. Machine Learning Stage (Stage 4):
   - Statistical generalization on text n-grams.
   - Provides probability score and calibrated confidence.
   - Differentiates Rule-Confirmed Malicious vs ML-Only Statistical Anomaly.
3. If no stage flags the input:
   - Output SAFE with explicit statement of coverage and static limitations.
"""

from typing import Dict, Any

from backend.stage1_rule import rule_based_detection
from backend.stage2_rule import check_dfa
from backend.stage3_cfg import check_cfg
from backend.model import predict_text


def detect_input(text: str) -> Dict[str, Any]:
    """
    Run the full 4-stage hybrid malicious input detector on the provided text.

    Returns structured dictionary with:
        - result: "Malicious" | "Safe"
        - risk_level: "High" | "Medium" | "Low" | "None"
        - finding_type: "Deterministic Rule Match" | "ML Statistical Finding" | "None"
        - stages: boolean flags for backward compatibility {regex, dfa, cfg, ml}
        - stage_details: full structured outputs for each stage
        - explanation: human-readable rationale
    """
    if text is None:
        text = ""

    # ========================================================
    # STAGE 1 - REGEX (Unit IV)
    # ========================================================
    stage1_res = rule_based_detection(text)
    regex_flag = bool(stage1_res.get("matched", False))

    # ========================================================
    # STAGE 2 - DFA (Unit III)
    # ========================================================
    stage2_res = check_dfa(text)
    dfa_flag = bool(stage2_res.get("matched", False))

    # ========================================================
    # STAGE 3 - CFG (Unit V)
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
    # HYBRID DECISION LOGIC & EXPLAINABILITY
    # ========================================================
    deterministic_match = regex_flag or dfa_flag or cfg_flag
    is_malicious = deterministic_match or ml_flag

    reasons = []
    if regex_flag:
        rule_names = [m["rule_name"] for m in stage1_res.get("matches", [])]
        reasons.append(f"Stage 1 (Regex): Matched {len(rule_names)} signature(s): {', '.join(rule_names[:3])}.")

    if dfa_flag:
        dfa_names = [m["dfa_name"] for m in stage2_res.get("matches", [])]
        reasons.append(f"Stage 2 (DFA): Accepted by finite automaton: {', '.join(dfa_names)}.")

    if cfg_flag:
        reasons.append("Stage 3 (CFG): Parser derived unauthorized SQL injection grammar structure.")

    if ml_flag:
        prob_pct = f"{ml_prob * 100:.1f}%" if ml_prob is not None else "High"
        if deterministic_match:
            reasons.append(f"Stage 4 (ML): Corroborated threat with {prob_pct} statistical malicious probability.")
        else:
            reasons.append(f"Stage 4 (ML): Flagged statistical anomaly with {prob_pct} malicious probability without deterministic rule match.")

    # Risk level & explanation
    if deterministic_match:
        final_result = "Malicious"
        risk_level = "High"
        finding_type = "Deterministic Rule Match"
        explanation = "Input was confirmed malicious by formal language rules: " + " ".join(reasons)
    elif ml_flag:
        final_result = "Malicious"
        risk_level = "Medium"
        finding_type = "ML Statistical Finding"
        explanation = (
            "Input exhibited significant statistical similarity to known malicious payloads in the ML dataset "
            f"(P(Malicious) = {ml_prob * 100:.1f}%), though no explicit Regex or DFA rule triggered."
        )
    else:
        final_result = "Safe"
        risk_level = "None"
        finding_type = "None"
        ml_safe_pct = f"{(1 - (ml_prob or 0.0)) * 100:.1f}%"
        explanation = (
            "Input passed all deterministic filters (Regex, DFA, CFG) and was classified as benign by the ML model "
            f"({ml_safe_pct} normal confidence). No known attack patterns were detected."
        )

    return {
        "result": final_result,
        "risk_level": risk_level,
        "finding_type": finding_type,
        "explanation": explanation,
        "reasons": reasons,
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