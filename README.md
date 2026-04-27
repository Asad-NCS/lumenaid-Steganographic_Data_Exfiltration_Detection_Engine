# LumenAid - Steganographic Data Exfiltration Detection Engine

## Overview
LumenAid is a hybrid detection platform for steganographic data exfiltration. It uses PostgreSQL for structured metadata and MongoDB for raw binary storage, with a four-signal scoring pipeline to flag suspicious files.

## Detection Model
LumenAid evaluates files with four statistical signals:
1. Signal 1: Shannon entropy spikes in binary chunks.
2. Signal 2: Chi-square deviations from normal file-type patterns.
3. Signal 3: Pattern consistency checks using SQL window functions.
4. Signal 4: File size anomalies relative to calibrated file-type averages.

## Requirements
Before running the project, install:
1. PostgreSQL on port `5432`
2. MongoDB on port `27017`
3. Python 3.10 or newer
4. Node.js 18 or newer

## Quick Start
This is the recommended path for Windows.

1. Open a terminal in the project root.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install dashboard dependencies:
   ```bash
   cd dashboard
   npm install
   cd ..
   ```
4. Start the full stack:
   ```bash
   .\run_project.bat
   ```

The launcher will try to start MongoDB if needed, then open the backend and dashboard in separate windows.

## If Auto-Start Fails
If the batch file cannot find MongoDB or your machine uses custom paths, use the manual fallback below.

Set environment variables in PowerShell first:
```powershell
$env:LUMENAID_PG_DSN = "host=localhost dbname=lumenaid user=postgres password=YOUR_PASSWORD"
$env:MONGOD_EXE = "C:\Path\To\MongoDB\bin\mongod.exe"
$env:LUMENAID_MONGO_DBPATH = "$PWD\.mongo-data"
$env:LUMENAID_MONGO_LOG = "$PWD\.mongo-data\mongod.log"
```

Then start each service manually:

1. MongoDB
   ```powershell
   if (!(Test-Path $env:LUMENAID_MONGO_DBPATH)) { New-Item -ItemType Directory -Force -Path $env:LUMENAID_MONGO_DBPATH | Out-Null }
   & "$env:MONGOD_EXE" --dbpath "$env:LUMENAID_MONGO_DBPATH" --bind_ip 127.0.0.1 --port 27017 --logpath "$env:LUMENAID_MONGO_LOG" --logappend
   ```

2. Backend API
   ```bash
   python -m uvicorn api.main:app --reload --port 8000
   ```

3. Dashboard
   ```bash
   cd dashboard
   npm install
   npm start
   ```

Open these URLs when the services are running:
1. Dashboard: `http://localhost:3000`
2. API docs: `http://127.0.0.1:8000/docs`

## Calibration
Calibration is required so the engine learns the local "normal" baseline.

1. Run the calibration script from the project root:
   ```bash
   python bulk_calibrate.py
   ```
2. The script scans the reference samples and builds the 3-sigma baseline used by the scoring system.

## Testing Workflow
1. Log in through the dashboard.
2. Verify the calibrated samples.
3. Upload a clean file and confirm it returns CLEAN.
4. Upload a file with hidden data and compare the alerts.
5. Use the entropy heatmap and hex dump view to inspect suspicious segments.

## Useful Environment Variables
These make the project easier to run on different machines:
- `LUMENAID_PG_DSN`: PostgreSQL connection string
- `LUMENAID_MONGO_URI`: MongoDB URI, default `mongodb://localhost:27017`
- `MONGOD_EXE`: Full path to `mongod.exe` if it is not on PATH
- `LUMENAID_MONGO_DBPATH`: Local Mongo data folder used by the launcher
- `LUMENAID_MONGO_LOG`: MongoDB log file path used by the launcher

## Architecture Notes
- PostgreSQL stores metadata, scores, and alerts.
- MongoDB stores raw binary chunks and telemetry.
- The API serves the dashboard and scans files through the engine pipeline.