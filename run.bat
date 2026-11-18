@echo off
title Malicious Input Detector
cd /d "%~dp0"
echo Starting Malicious Input Detector Backend...
start "" "%~dp0frontend\frontend.html"
call .venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause
