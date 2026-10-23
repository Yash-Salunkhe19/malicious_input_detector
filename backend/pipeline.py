"""
MAIN DETECTION PIPELINE

Stage 1 -> Regular Expression
Stage 2 -> DFA
Stage 3 -> CFG
Stage 4 -> Machine Learning
"""

import joblib
from pathlib import Path

from backend.stage1_rule import rule_based_detection
from backend.stage2_rule import check_dfa
from backend.stage3_cfg import check_cfg


# ============================================================
# MODEL PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "trained_model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"


# ============================================================
# LOAD ML MODEL
# ============================================================

model = joblib.load(MODEL_PATH)

vectorizer = joblib.load(VECTORIZER_PATH)


# ============================================================
# MAIN DETECTION FUNCTION
# ============================================================

def detect_input(text):

    # -----------------------------------------
    # STAGE 1 - REGEX
    # -----------------------------------------

    regex_result = rule_based_detection(text)


    # -----------------------------------------
    # STAGE 2 - DFA
    # -----------------------------------------

    dfa_result = check_dfa(text)


    # -----------------------------------------
    # STAGE 3 - CFG
    # -----------------------------------------

    cfg_result = check_cfg(text)


    # -----------------------------------------
    # STAGE 4 - MACHINE LEARNING
    # -----------------------------------------

    vectorized_input = vectorizer.transform([text])

    ml_prediction = model.predict(vectorized_input)[0]

    ml_result = int(ml_prediction) == 1


    # -----------------------------------------
    # FINAL DECISION
    # -----------------------------------------

    malicious = (

        regex_result
        or dfa_result
        or cfg_result
        or ml_result

    )


    if malicious:

        final_result = "Malicious"

    else:

        final_result = "Safe"


    # -----------------------------------------
    # RESPONSE
    # -----------------------------------------

    return {

        "result": final_result,

        "stages": {

            "regex": bool(regex_result),

            "dfa": bool(dfa_result),

            "cfg": bool(cfg_result),

            "ml": bool(ml_result)

        }

    }