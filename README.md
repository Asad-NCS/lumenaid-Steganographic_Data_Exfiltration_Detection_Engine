# LumenAid - Steganographic Data Exfiltration Detection Engine
 
## Team Members
- **Muhammad Asad Kashif** (500888)
- **Azaan Murtaza** (501196)
- **Hammad Ajmal** (508506)

---

## 🚀 Project Overview
LumenAid is an advanced, hybrid database-centric detection engine designed to identify steganographic data exfiltration. It combines the structured analytical power of **PostgreSQL** with the high-performance binary storage of **MongoDB** to provide a multi-signal threat intelligence platform.

### 🛡️ The 4-Signal Detection System
Unlike basic detectors, LumenAid uses four distinct statistical signals to verify file integrity:
1.  **Signal 1: Shannon Entropy Density** — Detects randomness spikes in binary chunks (Statement-level Trigger).
2.  **Signal 2: Chi-Square Distribution** — Identifies "Byte DNA" deviations from natural file-type patterns.
3.  **Signal 3: Pattern Consistency** — Detects sustained injection runs using complex SQL Window Functions.
4.  **Signal 4: File Size Delta** — Flags suspicious bloat relative to historical file-type averages.

---

## 🛠️ Execution Guide

### Prerequisites
1. **PostgreSQL** (Port `5432`)
2. **MongoDB** (Port `27017`)
3. **Python 3.10+**
4. **Node.js (v18+)**

### ⚡ One-Click Launch (Recommended for Windows)
Simply run the orchestrator script from the project root:
```bash
./run_project.bat
```
*This will automatically launch the Backend and the Frontend in their own windows.*

### 1. Database Initialization
Ensure your Postgres and Mongo instances are running. The system will automatically migrate the schema upon first backend startup.

### 2. System Calibration (Crucial Step)
Before running tests, you must calibrate the engine to your environment's "Normal" baseline using the 40 provided samples.
1. Navigate to the project root.
2. Run the calibration script:
   ```bash
   python bulk_calibrate.py
   ```
   *This script wipes the DB, scans the reference samples, and calculates the **3-Sigma Statistical Baseline** for all 4 signals.*

### 3. Backend Setup (FastAPI)
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the FastAPI server:
   ```bash
   uvicorn api.main:app --reload --port 8000
   ```

### 4. Frontend Setup (React Dashboard)
1. Navigate to the `dashboard` directory:
   ```bash
   cd dashboard
   npm install
   npm start
   ```
2. The dashboard will open at `http://localhost:3000`.

---

## 🔬 Testing Workflow
1. **Login**: Use the admin portal to access the command center.
2. **View Baselines**: Toggle **"VIEW CALIBRATED FILES"** to verify the 40 clean samples.
3. **Scan Test**: Upload a clean file. It should return **CLEAN (0/10)**.
4. **Attack Test**: Use `steghide` or similar tools to hide data in a file and upload it.
5. **Analyze**: Use the **Entropy Heatmap** and **Hex Dump Modal** to isolate the exact segments where the payload is hidden.

---

## 🏛️ Technical Architecture
- **Database Logic**: Entirely driven by PL/pgSQL triggers (`fn_analyze_segment_multi_signal`) for real-time threat scoring.
- **Hybrid Storage**: PostgreSQL handles the relational metadata and threat scores; MongoDB stores raw 4KB binary shards with GridFS-style referencing.
- **Analytics**: Materialized views (`vw_smoothed_anomalies`) provide smoothed trend analysis for the dashboard metrics.