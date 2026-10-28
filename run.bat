@echo off
title Digital Authenticity Analyst - Local Server
echo Starting Digital Authenticity Analyst on http://127.0.0.1:8000 ...
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload
pause
