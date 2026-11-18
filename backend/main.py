"""
FASTAPI APPLICATION
"""

from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from backend.pipeline import detect_input
from backend.api_scanner import scan_url


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="Malicious Input Detector API",
    description=(
        "Hybrid malicious input detection system "
        "using Regex, DFA, CFG and Machine Learning"
    ),
    version="1.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# FRONTEND FILE PATH
# ============================================================

FRONTEND_FILE = Path(__file__).resolve().parent.parent / "frontend" / "frontend.html"


# ============================================================
# INPUT MODEL
# ============================================================

class InputText(BaseModel):
    text: str


# ============================================================
# URL MODEL
# ============================================================

class URLInput(BaseModel):
    url: str


# ============================================================
# HOME / FRONTEND
# ============================================================

@app.get("/")
@app.get("/frontend")
@app.get("/app")
def serve_frontend():
    if FRONTEND_FILE.exists():
        return FileResponse(FRONTEND_FILE)
    return {
        "message": "Malicious Input Detector API is running"
    }


@app.get("/health")
def health():
    return {
        "message": "Malicious Input Detector API is running"
    }


# ============================================================
# TEXT DETECTION
# ============================================================

@app.post("/predict")
def predict(data: InputText):
    result = detect_input(data.text)
    return {
        "input": data.text,
        "result": result
    }


# ============================================================
# API URL SCANNER
# ============================================================

@app.post("/scan-url")
def scan_api_url(data: URLInput):
    result = scan_url(data.url)
    return result
