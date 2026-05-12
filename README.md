# 🛡️ LumenAid - Steganographic Data Exfiltration Detection Engine

> **Course:** CS 236: Advanced Database Management Systems  
> **Instructor:** Dr. Ayesha Hakim  
> **Team:** Muhammad Asad Kashif, Azaan Murtaza, Hammad Ajmal

LumenAid is a high-performance detection platform designed to identify hidden exfiltration attempts in benign files. Using **Statistical Steganalysis**, it flags anomalous data blocks that standard antivirus and DLP systems miss.

---

## 💎 Advanced Database Highlights (ADBMS Focus)
This project implements several advanced database concepts required for the course:
*   **Polyglot Persistence:** Hybrid architecture using **PostgreSQL** (Metadata/ACID) and **MongoDB** (Binary Chunks/High-throughput).
*   **Database-Side Logic:** Real-time detection using **PL/pgSQL Triggers** and Stored Procedures.
*   **Optimization:** **Materialized Views** for high-speed dashboard analytics.
*   **Dynamic Analytics:** Automated 3-Sigma threshold recalculation inside the database.

---

## 🚀 Quick Start (First-Time Setup)

### 1. Prerequisites
Ensure you have the following installed on your Windows machine:
*   **PostgreSQL 14+** (Default port: 5432)
*   **MongoDB 5+** (Default port: 27017)
*   **Python 3.10+**
*   **Node.js 18+**

### 2. Installation
Open a terminal in the project root:
```powershell
# Install Python backend dependencies
pip install -r requirements.txt

# Install Dashboard frontend dependencies
cd dashboard
npm install
cd ..
```

### 3. Initialize & Calibration (MANDATORY)
Before scanning, you must initialize the database baselines. Make sure your Postgres and Mongo servers are running, then run:
```powershell
python bulk_calibrate.py
```
*This script will create the tables, seed the users, and calibrate the detection engine.*

### 4. Launch the System
We provide a unified orchestrator to start the API and React Dashboard in one window:
```powershell
python run.py
```
Access the dashboard at: **`http://localhost:3000`**

---

## 👤 Login Credentials
The system comes pre-seeded with two accounts:
*   **Admin:** `admin` / Password: `password123`
*   **Analyst:** `analyst` / Password: `password123`

---

## 🛠️ Project Structure
*   `api/` - FastAPI REST Backend.
*   `db/` - SQL Migrations, Procedures, and Database Manager.
*   `engine/` - Core Entropy and Chi-Square detection logic.
*   `dashboard/` - React visualization interface.
*   `tools/` - Testing and maintenance scripts.

---

## ❓ Troubleshooting
*   **DB Connection Error:** Ensure PostgreSQL is running. You can set your connection string via the `LUMENAID_PG_DSN` environment variable.
*   **Mongo Not Found:** 
    *   **Option A (Automated):** Open **`run.py`** and update the `MONGOD_EXE` path to point to your local installation.
    *   **Option B (Manual):** Open **Command Prompt as Administrator** and run the `mongod` command manually before starting the system.
*   **Dashboard/UI Fail:** 
    *   If `run.py` fails to start the frontend, navigate to the directory manually: `cd dashboard` and run `npm start`.
*   **Port Conflicts:** Ensure ports 3000 (React) and 8000 (API) are available.

---
© 2026 LumenAid Team - NUST SEECS