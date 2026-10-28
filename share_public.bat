@echo off
title Digital Authenticity Analyst - Public Server
echo ==========================================================
echo Starting Digital Authenticity Analyst + Public Cloudflare Tunnel
echo ==========================================================
echo.
echo 1. Starting local FastAPI backend in new window...
start "FastAPI Server" cmd /k "python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000"
timeout /t 3 >nul

echo 2. Launching Cloudflare Public Tunnel...
echo Look for the 'https://xxxx.trycloudflare.com' link below:
echo ==========================================================
cloudflared.exe tunnel --url http://127.0.0.1:8000
pause
