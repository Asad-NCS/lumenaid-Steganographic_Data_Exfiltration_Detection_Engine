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

class FileRecord(BaseModel):
    file_id:      int
    file_name:    Optional[str]
    file_type:    str
    status:       str
    submitted_at: str            # ISO-8601 string

class SegmentRecord(BaseModel):
    segment_id:    int
    segment_index: int
    entropy_score: float
    raw_chunk_ref: str           # MongoDB ObjectId hex — never raw bytes

class AlertRecord(BaseModel):
    alert_id:     int
    segment_id:   Optional[int]
    severity:     str
    entropy_score: Optional[float]
    description:  Optional[str]
    created_at:   str

class FileAnalysisResponse(BaseModel):
    file_id:   int
    file_type: str
    status:    str
    baseline:  Optional[dict]    # {mean_entropy, threshold_sigma} if available
    segments:  List[SegmentRecord]
    alerts:    List[AlertRecord]


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
                SELECT b.mean_entropy, b.threshold_sigma, f.file_type
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
        file_type = "UNKNOWN"
        if context:
            threshold = float(context["mean_entropy"]) + float(context["threshold_sigma"])
            file_type = context["file_type"]

        is_suspicious = entropy > threshold
        
        if is_suspicious:
            verdict = f"Anomaly detected for {file_type}. Entropy ({round(entropy,2)}) exceeds threshold ({round(threshold,2)}). Likely hidden payload."
        elif entropy > 7.0:
            verdict = f"Normal {file_type} compression. High entropy is expected for this file format."
        else:
            verdict = f"Clean {file_type} segment. Entropy is within normal operational parameters."

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


@app.get(
    "/files",
    response_model=List[FileRecord],
    summary="List all scanned files with their current status",
    tags=["files"],
)
def list_files():
    """
    Returns every row from the files table, ordered newest-first.
    Includes file_name, file_type, status, and submitted_at timestamp.
    """
    conn = get_pg_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                file_id,
                file_name,
                file_type,
                status,
                submitted_at
            FROM   files
            ORDER  BY submitted_at DESC
            """
        )
        rows = cur.fetchall()

    return [
        FileRecord(
            file_id=r["file_id"],
            file_name=r["file_name"],
            file_type=r["file_type"],
            status=r["status"],
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
            "SELECT file_id, file_type, status FROM files WHERE file_id = %s",
            (file_id,),
        )
        file_row = cur.fetchone()

    if file_row is None:
        raise HTTPException(status_code=404, detail=f"file_id {file_id} not found")

    #--- 2. fetch baseline for colour-gradient anchoring ---
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT mean_entropy, threshold_sigma
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

    return FileAnalysisResponse(
        file_id=file_row["file_id"],
        file_type=file_row["file_type"],
        status=file_row["status"],
        baseline=baseline,
        segments=segments,
        alerts=alerts,
    )



# GET /health  — lightweight liveness probe 

@app.get("/health", tags=["ops"])
def health():
    return {"status": "ok", "service": "lumenaid-api"}
