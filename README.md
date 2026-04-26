# LumenAid - Steganographic Data Exfiltration Detection Engine
 
## Team Members
- **Muhammad Asad Kashif** (500888)
- **Azaan Murtaza** (501196)
- **Hammad Ajmal** (508506)

---

## Project Overview
LumenAid is a hybrid relational and non-relational database-centric detection engine. It analyses files for hidden steganographic data by calculating Shannon Entropy on raw binary chunks, storing the metadata in PostgreSQL and raw binaries in MongoDB. The anomaly detection logic is driven entirely by **PL/pgSQL triggers and stored procedures**.

## Execution Guide (Setup Instructions)

### Prerequisites
1. **PostgreSQL** (Running on default port `5432`)
2. **MongoDB** (Running on default port `27017`)
3. **Python 3.10+**
4. **Node.js (v18+)**

### 1. Database Setup
Ensure PostgreSQL and MongoDB are running. The FastAPI backend will automatically run the schema and seed scripts (`db/schema_migration.sql` and `db/seed_data.sql`) during startup if the database doesn't exist or isn't populated.

### 2. Backend Setup (FastAPI + Engine)
1. Navigate to the project root directory.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI server (it runs on port `8000` by default):
   ```bash
   uvicorn api.main:app --reload --port 8000
   ```

### 3. Frontend Setup (React Dashboard)
1. Open a new terminal and navigate to the `dashboard` directory:
   ```bash
   cd dashboard
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start the React development server:
   ```bash
   npm start
   ```
   The dashboard will automatically open at `http://localhost:3000`.

### 4. Testing the Engine
1. Go to `http://localhost:3000` in your browser.
2. Drag and drop any file (e.g., an EXE or a text file) into the upload zone.
3. The file will be ingested, chunked by the Python engine, and persisted to both MongoDB and PostgreSQL.
4. **PostgreSQL Triggers** (`fn_detect_entropy_anomalies`) will automatically detect anomalies against the threshold baselines and flag the file if suspicious!
5. Click on the uploaded file in the dashboard to see the full Entropy Heatmap and any resulting threat alerts.