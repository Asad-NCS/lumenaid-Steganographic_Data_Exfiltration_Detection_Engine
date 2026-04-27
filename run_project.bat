@echo off
title LumenAid Orchestrator
echo ==========================================
echo    LUMENAID SYSTEM - ONE-CLICK START
echo ==========================================
echo.

echo [1/2] Launching Backend (FastAPI on Port 8000)...
:: 'start' opens a new window so you can see the logs separately
start "LumenAid Backend" cmd /k "uvicorn api.main:app --port 8000"

echo [2/2] Launching Frontend (React on Port 3000)...
echo Please wait while the dashboard starts...
cd dashboard
npm start

pause
