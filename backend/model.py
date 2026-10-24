"""
MACHINE LEARNING INFERENCE MODULE (STAGE 4)
Loads trained model and vectorizer with reliable absolute paths.
Uses shared clean_text preprocessor and provides calibrated probability scores.
"""

from pathlib import Path
import joblib

from backend.preprocessor import clean_text

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "trained_model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"

model = None
vectorizer = None


def load_model_assets():
    global model, vectorizer
    if model is None and MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
    if vectorizer is None and VECTORIZER_PATH.exists():
        vectorizer = joblib.load(VECTORIZER_PATH)
    return model is not None and vectorizer is not None


# Eager load on module import if files exist
load_model_assets()


def predict_text(text: str):
    """
    Run ML inference on input text.
    
    Returns:
        dict with:
            is_malicious (bool)
            verdict ("Malicious" | "Normal")
            confidence (float 0.0 - 1.0)
            malicious_probability (float 0.0 - 1.0)
            model_type (str)
    """
    if not load_model_assets():
        return {
            "is_malicious": False,
            "verdict": "Unknown",
            "confidence": 0.0,
            "malicious_probability": 0.0,
            "error": "Model assets not loaded"
        }

    cleaned = clean_text(text)
    
    # Handle empty input
    if not cleaned:
        return {
            "is_malicious": False,
            "verdict": "Normal",
            "confidence": 1.0,
            "malicious_probability": 0.0,
            "model_type": type(model).__name__
        }

    vec = vectorizer.transform([cleaned])
    prediction = int(model.predict(vec)[0])
    
    # Probability estimation if supported
    malicious_prob = None
    confidence = 0.5
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vec)[0]
        # class 1 = malicious, class 0 = normal
        malicious_prob = float(probs[1])
        confidence = float(probs[prediction])
    else:
        malicious_prob = 1.0 if prediction == 1 else 0.0
        confidence = 1.0

    is_mal = (prediction == 1)
    return {
        "is_malicious": is_mal,
        "verdict": "Malicious" if is_mal else "Normal",
        "confidence": round(confidence, 4),
        "malicious_probability": round(malicious_prob, 4) if malicious_prob is not None else None,
        "model_type": type(model).__name__
    }