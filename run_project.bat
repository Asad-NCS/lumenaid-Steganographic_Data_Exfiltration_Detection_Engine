@echo off
title LumenAid Orchestrator
setlocal

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ==========================================
echo    LUMENAID SYSTEM - ONE-CLICK START
echo ==========================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
	echo ERROR: Python is not installed or not in PATH.
	echo Install Python 3.10+ and try again.
	pause
	exit /b 1
)

where npm >nul 2>nul
if %errorlevel% neq 0 (
	echo ERROR: npm is not installed or not in PATH.
	echo Install Node.js 18+ and try again.
	pause
	exit /b 1
)

if not defined LUMENAID_MONGO_DBPATH set "LUMENAID_MONGO_DBPATH=%ROOT%.mongo-data"
if not defined LUMENAID_MONGO_LOG set "LUMENAID_MONGO_LOG=%LUMENAID_MONGO_DBPATH%\mongod.log"
if not exist "%LUMENAID_MONGO_DBPATH%" mkdir "%LUMENAID_MONGO_DBPATH%"

echo [1/3] Checking MongoDB (Port 27017)...
call :is_port_open 27017
if %errorlevel% equ 0 (
	echo MongoDB already running.
) else (
	call :find_mongod
	if defined MONGOD_EXE (
		echo Starting MongoDB in a new window...
		start "LumenAid MongoDB" cmd /k "\"%MONGOD_EXE%\" --dbpath \"%LUMENAID_MONGO_DBPATH%\" --bind_ip 127.0.0.1 --port 27017 --logpath \"%LUMENAID_MONGO_LOG%\" --logappend"
	) else (
		echo WARNING: Could not find mongod.exe.
		echo Start MongoDB manually, or set MONGOD_EXE env var, or add mongod to PATH.
	)
)

echo [2/3] Launching Backend (FastAPI on Port 8000)...
start "LumenAid Backend" cmd /k "cd /d \"%ROOT%\" && python -m uvicorn api.main:app --reload --port 8000"

echo [3/3] Launching Frontend (React on Port 3000)...
echo Please wait while the dashboard starts...
start "LumenAid Frontend" cmd /k "cd /d \"%ROOT%dashboard\" && npm install && npm start"

echo.
echo All services have been started.
echo Close the opened windows to stop the project.
pause

exit /b 0

:is_port_open
netstat -ano | find ":%~1" | find "LISTENING" >nul
if %errorlevel% equ 0 (
	exit /b 0
)
exit /b 1

:find_mongod
if defined MONGOD_EXE if exist "%MONGOD_EXE%" exit /b 0

for /f "delims=" %%I in ('where mongod 2^>nul') do (
	set "MONGOD_EXE=%%I"
	exit /b 0
)

for /d %%D in ("%ProgramFiles%\MongoDB\Server\*") do (
	if exist "%%~fD\bin\mongod.exe" set "MONGOD_EXE=%%~fD\bin\mongod.exe"
)

if defined ProgramFiles(x86) (
	for /d %%D in ("%ProgramFiles(x86)%\MongoDB\Server\*") do (
		if exist "%%~fD\bin\mongod.exe" set "MONGOD_EXE=%%~fD\bin\mongod.exe"
	)
)

exit /b 0
