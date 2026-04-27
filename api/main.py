#basically the API that connects everything
"""
LumenAid — Steganographic Data Exfiltration Detection Engine
api/main.py

FastAPI application — the HTTP display layer that sits in front of the
engine + database layers.  Exposes three endpoints:

  POST /upload                     — accept a file, run the scan pipeline
  GET  /files                      — list all scanned files + status
  GET  /files/{file_id}/analysis   — segments (ordered) + alerts for one file

Architecture constraints (ARCHITECTURE.md):
  * PostgreSQL  → structured metadata (files, segments, alerts, baselines)
  * MongoDB     → raw binary chunks  (handled transparently by DatabaseManager)
  * segments.raw_chunk_ref is VARCHAR(24); never expose raw_bytes over HTTP.

Run locally:
  uvicorn api.main:app --reload --port 8000

Environment variables (can also be placed in a .env and loaded with python-dotenv):
  LUMENAID_PG_DSN        — postgres connection string
  LUMENAID_MONGO_URI     — mongodb URI
  LUMENAID_MONGO_DB      — mongodb database name  (default: lumenaid)
  LUMENAID_DEFAULT_USER  — postgres user_id used for uploads  (default: 1)
  LUMENAID_UPLOAD_DIR    — temp directory for uploaded files  (default: /tmp/lumenaid)
"""

import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from typing import List, Optional

import psycopg2
import psycopg2.extras
import bcrypt
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db.database_manager import DatabaseManager
from engine.scan_pipeline import ScanPipeline


# Configuration — read from environment with sane defaults for local dev

PG_DSN        = os.getenv("LUMENAID_PG_DSN",       "host=localhost dbname=lumenaid user=postgres password=3568")
MONGO_URI     = os.getenv("LUMENAID_MONGO_URI",    "mongodb://localhost:27017")
MONGO_DB      = os.getenv("LUMENAID_MONGO_DB",     "lumenaid")
DEFAULT_USER  = int(os.getenv("LUMENAID_DEFAULT_USER", "1"))
UPLOAD_DIR    = os.getenv("LUMENAID_UPLOAD_DIR",   tempfile.gettempdir())

#ensure_upload_dir exists
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Application-level shared state 

_db_manager: Optional[DatabaseManager] = None


from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def ensure_database_and_schema():
    # Parse DSN (assuming simple key=value format)
    dsn_parts = dict(part.split('=') for part in PG_DSN.split())
    target_db = dsn_parts.get('dbname', 'lumenaid')
    
    # Connect to default 'postgres' database to check/create target DB
    temp_dsn_parts = dsn_parts.copy()
    temp_dsn_parts['dbname'] = 'postgres'
    temp_dsn = ' '.join(f"{k}={v}" for k, v in temp_dsn_parts.items())
    
    try:
        conn = psycopg2.connect(temp_dsn)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
            if not cur.fetchone():
                print(f"Database '{target_db}' does not exist. Creating it...")
                # psycopg2 requires database names to be safely formatted or just standard strings without injection risk.
                cur.execute(f"CREATE DATABASE {target_db}")
                print(f"Database '{target_db}' created successfully.")
        conn.close()
    except Exception as e:
        print(f"Warning: Could not check/create database (auth failed or server down). Error: {e}")

    # Now connect to the actual database and run schema_migration.sql
    try:
        conn = psycopg2.connect(PG_DSN)
        with conn.cursor() as cur:
            schema_path = os.path.join(os.path.dirname(__file__), '..', 'db', 'schema_migration.sql')
            if os.path.exists(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                # Run the schema script
                cur.execute(schema_sql)
                print("Schema validation/migration completed successfully.")
            else:
                print(f"Warning: Schema file not found at {schema_path}")

            seed_path = os.path.join(os.path.dirname(__file__), '..', 'db', 'seed_data.sql')
            if os.path.exists(seed_path):
                with open(seed_path, 'r', encoding='utf-8') as f:
                    seed_sql = f.read()
                # Run the seed script
                cur.execute(seed_sql)
                print("Seed data loaded successfully.")
            else:
                print(f"Warning: Seed file not found at {seed_path}")

            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error: Could not run schema migration. Details: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure DB and Schema exist before initializing the application
    ensure_database_and_schema()
    
    #open_database connections once at startup; close cleanly on shutdown.
    global _db_manager
    _db_manager = DatabaseManager(
        pg_dsn=PG_DSN,
        mongo_uri=MONGO_URI,
        mongo_db_name=MONGO_DB,
    )
    yield
    if _db_manager is not None:
        _db_manager.close()


def get_db() -> DatabaseManager:
    if _db_manager is None:
        raise HTTPException(status_code=503, detail="Database not initialised")
    return _db_manager


def get_pg_conn():
    """Return a live psycopg2 connection from the shared DatabaseManager."""
    return get_db()._connect_postgres()


 
# FastAPI application 

app = FastAPI(
    title="LumenAid — Detection API",
    description="Steganographic data exfiltration detection engine REST interface.",
    version="1.0.0",
    lifespan=lifespan,
)

#allow_the React dev server (localhost:3000) to call us without CORS errors.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 
# Pydantic response models
# 

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    user_id: int
    username: str
    role: str
    token: str

class HexDumpResponse(BaseModel):
    mongo_id: str
    hex_dump: str
    strings: List[str]
    entropy: float
    verdict: str
    is_suspicious: bool

class UploadResponse(BaseModel):
    file_id:        int
    status:         str          # "clean" | "flagged" | "error"
    total_segments: int
    alerts_raised:  int
    message:        str

class SegmentRecord(BaseModel):
    segment_id:       int
    segment_index:    int
    entropy_score:    float
    chi_square_score: float
    raw_chunk_ref:    str

class AlertRecord(BaseModel):
    alert_id:     int
    segment_id:   Optional[int]
    severity:     str
    entropy_score: Optional[float]
    description:  Optional[str]
    created_at:   str

class FileAnalysisResponse(BaseModel):
    file_id:       int
    file_type:     str
    status:        str
    threat_score:  int
    risk_level:    str
    baseline:      Optional[dict]
    segments:      List[SegmentRecord]
    alerts:        List[AlertRecord]
    signals_fired: dict   # {signal_1: bool, signal_2: bool, signal_3: bool, signal_4: bool}


# 
# POST /login
# 

@app.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate user and return role",
    tags=["auth"],
)
def login(req: LoginRequest):
    conn = get_pg_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT user_id, username, password_hash, role FROM users WHERE username = %s", (req.username,))
        user = cur.fetchone()
        
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    # Check bcrypt hash
    try:
        if not bcrypt.checkpw(req.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid password format")
        
    return LoginResponse(
        user_id=user["user_id"],
        username=user["username"],
        role=user["role"],
        token="demo-token-123"
    )

 
# GET /chunks/{chunk_id}/hex 

@app.get(
    "/chunks/{chunk_id}/hex",
    response_model=HexDumpResponse,
    summary="Get human and raw analysis of a segment",
    tags=["analysis"],
)
def get_chunk_hex(chunk_id: str):
    db = get_db()
    try:
        raw_bytes = db.get_chunk_bytes(chunk_id)
        if not raw_bytes:
            raise HTTPException(status_code=404, detail="Chunk not found")
            
        # 1. Generate Hex Dump
        hex_lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f"{i:08x}  {hex_str:<47}  |{ascii_str}|")
            
        # 2. Extract Human Readable Strings (min length 4)
        import re
        # Find sequences of 4 or more printable ASCII characters
        found_strings = re.findall(b"[\\x20-\\x7E]{4,}", raw_bytes)
        decoded_strings = [s.decode('ascii', errors='ignore') for s in found_strings]
        
        # 3. Smart Heuristic Verdict (Context-Aware)
        # Fetch the baseline for this specific segment to avoid false positives
        conn = get_pg_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT b.mean_entropy, b.threshold_sigma, b.mean_chi, b.sigma_chi, f.file_type, s.chi_square_score
                FROM segments s
                JOIN files f ON s.file_id = f.file_id
                JOIN baselines b ON f.file_type = b.file_type
                WHERE s.raw_chunk_ref = %s
                LIMIT 1
            """, (chunk_id,))
            context = cur.fetchone()

        import math
        freq = [0] * 256
        for b in raw_bytes: freq[b] += 1
        entropy = 0.0
        for c in freq:
            if c > 0:
                p = c / len(raw_bytes)
                entropy -= p * math.log2(p)
        
        # Compare against real baseline
        threshold = 7.5 # fallback
        chi_threshold = 50.0
        file_type = "UNKNOWN"
        if context:
            threshold = float(context["mean_entropy"]) + 3.0 * float(context["threshold_sigma"])
            chi_threshold = float(context["mean_chi"] or 0) + 3.0 * float(context["sigma_chi"] or 0)
            file_type = context["file_type"]

        # Smart multi-signal suspicion check
        is_suspicious = (entropy > threshold) or (float(context.get("chi_square_score") or 0) > chi_threshold and float(context.get("chi_square_score") or 0) > 5.0)

        if is_suspicious:
            reason = "Entropy" if entropy > threshold else "Chi-Square"
            verdict = f"Anomaly detected for {file_type} via {reason}. Significant evidence of hidden payload."
        elif entropy > threshold - 0.5:
            verdict = f"Suspicious {file_type} segment. Entropy is near the 3-sigma limit. Worth manual inspection."
        else:
            verdict = f"Clean {file_type} segment. Entropy and byte-DNA are within calibrated 3-sigma parameters."

        return HexDumpResponse(
            mongo_id=chunk_id,
            hex_dump='\n'.join(hex_lines),
            strings=decoded_strings[:20], 
            entropy=round(entropy, 4),
            verdict=verdict,
            is_suspicious=is_suspicious
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get(
    "/telemetry",
    summary="Get system scan logs from MongoDB (Admin only)",
    tags=["admin"],
)
def get_telemetry(limit: int = 15):
    db = get_db()
    try:
        return db.get_telemetry(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

 
# POST /upload
 

@app.post(
    "/upload",
    response_model=UploadResponse,
    summary="Upload a file and run the entropy scan pipeline",
    tags=["scanning"],
)
async def upload_file(file: UploadFile = File(...)):
    """
    Accepts a multipart/form-data file upload.

    Workflow:
      1. Save the file to a temp path on disk.
      2. Call ScanPipeline.run(file_path, user_id=DEFAULT_USER).
      3. Delete the temp file.
      4. Return file_id + final status (CLEAN / FLAGGED).
    """
    #build_a deterministic temp path that keeps the original extension
    _, ext = os.path.splitext(file.filename or "upload.bin")
    tmp_path = os.path.join(UPLOAD_DIR, f"lumenaid_upload_{os.getpid()}{ext}")

    try:
        #write_the uploaded bytes to disk so LumenEngine can open it
        with open(tmp_path, "wb") as out:
            shutil.copyfileobj(file.file, out)

        pipeline = ScanPipeline(db_manager=get_db())
        result   = pipeline.run(file_path=tmp_path, user_id=DEFAULT_USER)

    finally:
        #always_clean up the temp file, even on error
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if result.status == "error":
        raise HTTPException(status_code=500, detail=result.error)

    # Persist original client filename for dashboard listing.
    try:
        conn = get_pg_conn()
        if conn.status != psycopg2.extensions.STATUS_READY:
            conn.rollback()
        safe_name = os.path.basename((file.filename or "").strip())
        if not safe_name:
            safe_name = f"scan_{result.file_id}.bin"
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE files SET file_name = %s WHERE file_id = %s",
                (safe_name, result.file_id),
            )
            conn.commit()
    except Exception:
        # Non-fatal: scan result is still valid even if filename update fails.
        pass

    return UploadResponse(
        file_id=result.file_id,
        status=result.status.upper(),
        total_segments=result.total_segments,
        alerts_raised=result.flagged_count,
        message=(
            f"Scan complete. {result.flagged_count} anomalous segment(s) detected."
            if result.flagged_count
            else "Scan complete. File appears clean."
        ),
    )


 
# GET /files

class FileRecord(BaseModel):
    file_id:      int
    file_name:    Optional[str] = None
    file_type:    str
    status:       str
    threat_score: int
    risk_level:   str
    is_calibrated: bool
    submitted_at: str


def _generated_file_name(file_id: int, file_type: Optional[str]) -> str:
    ext_map = {
        "TEXT": "txt",
        "TXT": "txt",
        "JPG": "jpg",
        "JPEG": "jpg",
        "PNG": "png",
        "PDF": "pdf",
    }
    ext = ext_map.get((file_type or "").upper(), "bin")
    return f"scan_{file_id}.{ext}"

@app.get(
    "/files",
    response_model=List[FileRecord],
    summary="List all scanned files with their current status",
    tags=["files"],
)
def list_files():
    conn = get_pg_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                file_id, file_name, file_type, status,
                threat_score, risk_level, submitted_at,
                is_calibrated
            FROM files
            ORDER BY submitted_at DESC
            """
        )
        rows = cur.fetchall()

    # Backfill old rows that still have null/blank names.
    missing_name_rows = [r for r in rows if not (r["file_name"] and str(r["file_name"]).strip())]
    if missing_name_rows:
        conn = get_pg_conn()
        if conn.status != psycopg2.extensions.STATUS_READY:
            conn.rollback()
        with conn.cursor() as cur:
            for r in missing_name_rows:
                generated = _generated_file_name(r["file_id"], r.get("file_type"))
                cur.execute(
                    "UPDATE files SET file_name = %s WHERE file_id = %s",
                    (generated, r["file_id"]),
                )
                r["file_name"] = generated
            conn.commit()

    return [
        FileRecord(
            file_id=r["file_id"],
            file_name=r["file_name"] or _generated_file_name(r["file_id"], r.get("file_type")),
            file_type=r["file_type"],
            status=r["status"],
            threat_score=r["threat_score"] or 0,
            risk_level=r["risk_level"] or "CLEAN",
            is_calibrated=r["is_calibrated"],
            submitted_at=r["submitted_at"].isoformat(),
        )
        for r in rows
    ]

 
# GET /files/{file_id}/analysis


@app.get(
    "/files/{file_id}/analysis",
    response_model=FileAnalysisResponse,
    summary="Fetch segment entropy data and alerts for one file",
    tags=["files"],
)
def get_file_analysis(file_id: int):
    """
    Returns:
      * segments  — all rows from the segments table, ordered by segment_index
                    (ordering is critical for the heatmap to be accurate).
      * alerts    — all rows from the alerts table for this file.
      * baseline  — the mean_entropy and threshold_sigma for this file's type
                    (the dashboard needs these to drive the colour gradient).
    """
    conn = get_pg_conn()

    #--- 1. fetch the parent file record ---
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT file_id, file_type, status, threat_score, risk_level FROM files WHERE file_id = %s",
            (file_id,),
        )
        file_row = cur.fetchone()

    if file_row is None:
        raise HTTPException(status_code=404, detail=f"file_id {file_id} not found")

    #--- 2. fetch baseline for colour-gradient anchoring ---
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT mean_entropy, threshold_sigma, mean_chi, sigma_chi
            FROM   baselines
            WHERE  file_type = %s
            LIMIT  1
            """,
            (file_row["file_type"],),
        )
        baseline_row = cur.fetchone()

    baseline = (
        {
            "mean_entropy":    float(baseline_row["mean_entropy"]),
            "threshold_sigma": float(baseline_row["threshold_sigma"]),
            "mean_chi":        float(baseline_row["mean_chi"] or 0),
            "sigma_chi":       float(baseline_row["sigma_chi"] or 0),
        }
        if baseline_row
        else None
    )

    #--- 3. fetch segments ordered by segment_index (critical for heatmap) ---
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                segment_id,
                segment_index,
                entropy_score,
                chi_square_score,
                raw_chunk_ref
            FROM   segments
            WHERE  file_id = %s
            ORDER  BY segment_index ASC
            """,
            (file_id,),
        )
        seg_rows = cur.fetchall()

    segments = [
        SegmentRecord(
            segment_id=r["segment_id"],
            segment_index=r["segment_index"],
            entropy_score=float(r["entropy_score"]),
            chi_square_score=float(r["chi_square_score"] or 0),
            raw_chunk_ref=r["raw_chunk_ref"],
        )
        for r in seg_rows
    ]

    #--- 4. fetch all alerts for this file ---
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                alert_id,
                segment_id,
                severity,
                entropy_score,
                description,
                created_at
            FROM   alerts
            WHERE  file_id = %s
            ORDER  BY created_at DESC
            """,
            (file_id,),
        )
        alert_rows = cur.fetchall()

    alerts = [
        AlertRecord(
            alert_id=r["alert_id"],
            segment_id=r["segment_id"],
            severity=r["severity"],
            entropy_score=float(r["entropy_score"]) if r["entropy_score"] is not None else None,
            description=r["description"],
            created_at=r["created_at"].isoformat(),
        )
        for r in alert_rows
    ]

    #--- 5. compute which signals fired ---
    # Signal 1: any segment entropy exceeded 3-sigma threshold
    threshold = (baseline["mean_entropy"] + 3.0 * baseline["threshold_sigma"]) if baseline else 7.5
    s1 = any(float(r["entropy_score"]) > threshold for r in seg_rows)
    
    # Signal 2: any segment chi_square exceeded 3-sigma threshold
    chi_threshold = (baseline["mean_chi"] + 3.0 * baseline["sigma_chi"]) if baseline else 50.0
    s2 = any(float(r["chi_square_score"] or 0) > chi_threshold and float(r["chi_square_score"] or 0) > 5.0 for r in seg_rows)
    # Signal 3 & 4: check alert descriptions
    alert_descs = " ".join(r["description"] or "" for r in alert_rows)
    s3 = "Signal 3" in alert_descs or "Pattern Consistency" in alert_descs
    s4 = "Signal 4" in alert_descs or "size anomaly" in alert_descs.lower()

    return FileAnalysisResponse(
        file_id=file_row["file_id"],
        file_type=file_row["file_type"],
        status=file_row["status"],
        threat_score=int(file_row["threat_score"] or 0),
        risk_level=file_row["risk_level"] or "CLEAN",
        baseline=baseline,
        segments=segments,
        alerts=alerts,
        signals_fired={
            "signal_1_entropy":  s1,
            "signal_2_chi":      s2,
            "signal_3_pattern":  s3,
            "signal_4_size":     s4,
        },
    )



# GET /health  — lightweight liveness probe 

@app.get("/health", tags=["ops"])
def health():
    return {"status": "ok", "service": "lumenaid-api"}
