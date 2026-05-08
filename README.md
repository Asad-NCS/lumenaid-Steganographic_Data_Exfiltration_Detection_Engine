# LumenAid - Steganographic Data Exfiltration Detection Engine

## Overview
LumenAid is a high-performance detection platform designed to identify steganographic data exfiltration through advanced statistical analysis. Built with a **Polyglot Persistence** architecture, it leverages **PostgreSQL** for complex detection logic and structured metadata, and **MongoDB** for high-volume binary storage and telemetry.

## Detection Model: The Four-Signal Pipeline
LumenAid evaluates every file through a sophisticated four-signal scoring engine:

1.  **Signal 1: Shannon Entropy Spikes** — Detects localized randomness in binary chunks that deviate from the file-type baseline.
2.  **Signal 2: Chi-Square Anomaly Detection** — Measures statistical deviations in byte distributions to identify hidden payloads in high-entropy files.
3.  **Signal 3: Pattern Consistency (Sustained Runs)** — Uses SQL Window Functions to identify consecutive anomalous segments, distinguishing real payloads from natural noise.
4.  **Signal 4: File Size Delta Analysis** — Flags files that are significantly larger than the calibrated average for their type.

## Architecture Highlights
- **PostgreSQL**: Stores users, metadata, and performs heavy detection logic via **PL/pgSQL Triggers** and window functions.
- **MongoDB**: Stores raw file chunks (`raw_chunk_ref`) and detailed analysis telemetry for forensic inspection.
- **Calibration Engine**: Learns the "Normal" baseline for your environment, reducing false positives in benign high-entropy files (The "Entropy Gate").

---

## Quick Start (Windows)

### 1. Prerequisites
- **PostgreSQL** 14+ (Port 5432)
- **MongoDB** 5+ (Port 27017)
- **Python** 3.10+
- **Node.js** 18+

### 2. Installation
Open your terminal in the project root:
```powershell
# Install Python dependencies
pip install -r requirements.txt

# Install Dashboard dependencies
cd dashboard
npm install
cd ..
```

### 3. Launching the System
> [!IMPORTANT]
> If this is your first time running the project, you **must** run `python bulk_calibrate.py` first (see section below) to initialize the detection baselines.

We provide a unified orchestrator to start the full stack (Mongo, API, and React) in one window:
```powershell
python run.py  # or 'py run.py'
```
*Press `Ctrl+C` in this window to stop all services gracefully.*

---

## Calibration & Testing
LumenAid is **calibration-dependent**. Before scanning new files, you must build a baseline:

1.  **Run Calibration**:
    ```powershell
    python bulk_calibrate.py
    ```
    This script analyzes clean samples and calculates the **3-Sigma** thresholds used for detection.

2.  **Access the Dashboard**:
    - URL: `http://localhost:3000`
    - API Documentation: `http://127.0.0.1:8000/docs`

3.  **Upload & Analyze**:
    - Use the dashboard to upload files.
    - View the **Entropy Heatmap** and **Hex Dump** for any flagged segments to inspect the suspicious data.

## Environment Variables
If your database configuration differs from the defaults, set these in your environment:
- `LUMENAID_PG_DSN`: PostgreSQL connection string (e.g., `host=localhost dbname=lumenaid user=postgres password=...`)
- `LUMENAID_MONGO_URI`: MongoDB connection URI
- `MONGOD_EXE`: Path to `mongod.exe` if not in PATH

---

## Technical Notes
- **Data Integrity**: Uses PostgreSQL RLS (Row Level Security) to ensure analysts only see their own scan results.
- **Performance**: High-speed chunking and parallel database writes allow for scanning large files in seconds.
- **Extensibility**: New file types can be added to the `file_type_registry` to extend detection capabilities.