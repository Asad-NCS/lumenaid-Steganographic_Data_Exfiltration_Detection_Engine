import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from engine.lumen_engine import LumenEngine
from db.database_manager import DatabaseManager


#severity_thresholds — how many sigma above the baseline mean triggers each level.
#these_are starting defaults; real baselines live in the postgres baselines table.
SIGMA_HIGH     = 3.0  #> mean + 3σ → HIGH
SIGMA_MEDIUM   = 2.0  #> mean + 2σ → MEDIUM
SIGMA_LOW      = 1.0  #> mean + 1σ → LOW


@dataclass
class ScanResult:
    #returned_by ScanPipeline.run() — everything the caller needs to know.
    file_id:        int
    total_segments: int
    alerts_raised:  List[Dict]        = field(default_factory=list)
    flagged_count:  int               = 0
    status:         str               = "clean"  #"clean" | "flagged" | "error"
    error:          Optional[str]     = None


class ScanPipeline:
    #orchestrates_the full lumenaid scan workflow:
    #  1. lumenengine   — read file, chunk it, compute entropy per segment
    #  2. databasemanager — persist chunks to mongo + file/segments to postgres
    #  3. alert_generation — handled purely by postgres triggers during insert
    #  4. result_fetch  — fetch the final status and alert count from postgres

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager


    # LEGACY PYTHON-DRIVEN ALERT LOGIC 
    # (Commented out in favor of database-centric PostgreSQL Triggers)
    # Kept here just in case it is needed in the future.

    # 
    # def _fetch_baseline(self, pg_conn, file_type: str) -> Optional[Dict]:
    #     with pg_conn.cursor() as cur:
    #         cur.execute(
    #             """
    #             SELECT mean_entropy, threshold_sigma
    #             FROM   baselines
    #             WHERE  file_type = %s
    #             LIMIT  1
    #             """,
    #             (file_type,),
    #         )
    #         row = cur.fetchone()
    #     if row is None:
    #         return None
    #     return {"mean_entropy": float(row[0]), "threshold_sigma": float(row[1])}
    # 
    # def _classify_severity(
    #     self, entropy: float, mean: float, sigma: float
    # ) -> Optional[str]:
    #     deviation = entropy - mean
    #     if deviation > SIGMA_HIGH * sigma:
    #         return "HIGH"
    #     if deviation > SIGMA_MEDIUM * sigma:
    #         return "MEDIUM"
    #     if deviation > SIGMA_LOW * sigma:
    #         return "LOW"
    #     return None
    # 
    # def _write_alerts(self, pg_conn, file_id: int, alerts: List[Dict]):
    #     if not alerts:
    #         return
    #     import psycopg2.extras
    #     rows = [(file_id, a["severity"], a["entropy_score"]) for a in alerts]
    #     with pg_conn.cursor() as cur:
    #         psycopg2.extras.execute_values(
    #             cur,
    #             """
    #             INSERT INTO alerts (file_id, severity, entropy_score)
    #             VALUES %s
    #             """,
    #             rows,
    #         )
    #     pg_conn.commit()
    # 
    # def _update_file_status(self, pg_conn, file_id: int, status: str):
    #     with pg_conn.cursor() as cur:
    #         cur.execute(
    #             """
    #             UPDATE files
    #             SET    status = %s
    #             WHERE  file_id = %s
    #             """,
    #             (status, file_id),
    #         )
    #     pg_conn.commit()

    #public api

    def run(self, file_path: str, user_id: int) -> ScanResult:
        #main_entry point for a single file scan.
        #
        #args:
        #  file_path — absolute or relative path to the file to scan
        #  user_id   — postgres users.user_id of the requesting user
        #
        #returns a ScanResult dataclass with all findings.

        if not os.path.isfile(file_path):
            return ScanResult(
                file_id=-1,
                total_segments=0,
                status="error",
                error=f"file not found: {file_path}",
            )

        #derive_file_type from extension (lowercase, no dot)
        _, ext = os.path.splitext(file_path)
        ext_upper = ext.lstrip(".").upper()
        
        type_mapping = {
            "TXT": "TEXT",
            "CSV": "TEXT",
            "LOG": "TEXT",
            "JPEG": "JPG",
        }
        mapped_type = type_mapping.get(ext_upper, ext_upper)
        supported_types = {"TEXT", "JPG", "PDF", "PNG"}
        
        if mapped_type not in supported_types:
            return ScanResult(
                file_id=-1,
                total_segments=0,
                status="error",
                error=f"Unsupported file type: {ext}. Only TXT, JPG, and PDF are allowed.",
            )
        file_type = mapped_type

        import time
        scan_start_time = time.time()

        try:
            #step 1: entropy analysis via lumenengine
            engine = LumenEngine(file_path)
            segments = engine.analyze()
            analysis_duration_ms = int((time.time() - scan_start_time) * 1000)

            #step 2: hybrid persistence (mongo chunks + pg files/segments)
            file_size = os.path.getsize(file_path)
            db_start_time = time.time()
            file_id = self.db.persist(
                user_id=user_id,
                file_type=file_type,
                file_size=file_size,
                segments=segments,
            )
            db_duration_ms = int((time.time() - db_start_time) * 1000)

            # LEGACY PYTHON ALERT CLASSIFICATION (Commented out)

            # pg_conn = self.db._connect_postgres()
            # baseline = self._fetch_baseline(pg_conn, file_type)
            # alerts_raised: List[Dict] = []
            # if baseline is None:
            #     print(f"[lumenaid] warning: no baseline found for type '{file_type}'. skipping alert classification.")
            # else:
            #     mean  = baseline["mean_entropy"]
            #     sigma = baseline["threshold_sigma"]
            #     for seg in segments:
            #         severity = self._classify_severity(seg["entropy_score"], mean, sigma)
            #         if severity is not None:
            #             alerts_raised.append({"segment_index": seg["segment_index"], "entropy_score": seg["entropy_score"], "severity": severity})
            #     self._write_alerts(pg_conn, file_id, alerts_raised)
            # final_status = "FLAGGED" if alerts_raised else "CLEAN"
            # self._update_file_status(pg_conn, file_id, final_status)

            #step 3: signal 3 — segment pattern consistency check
            #
            # A natural file may have ONE high-entropy chunk (e.g., a compressed header).
            # An injected payload produces a SUSTAINED run of anomalous chunks.
            # This query uses a SQL window function to find runs of 3+ consecutive
            # segments that all exceed the baseline threshold.
            pg_conn = self.db._connect_postgres()
            with pg_conn.cursor() as cur:
                cur.execute(
                    """
                    WITH baseline AS (
                        SELECT mean_entropy + threshold_sigma AS threshold
                        FROM baselines
                        WHERE file_type = %s
                        LIMIT 1
                    ),
                    flagged_segments AS (
                        SELECT
                            segment_index,
                            segment_index
                                - ROW_NUMBER() OVER (ORDER BY segment_index) AS grp
                        FROM segments, baseline
                        WHERE file_id = %s
                          AND entropy_score > baseline.threshold
                    ),
                    runs AS (
                        SELECT grp, COUNT(*) AS run_length
                        FROM flagged_segments
                        GROUP BY grp
                        HAVING COUNT(*) >= 3
                    )
                    SELECT COUNT(*) FROM runs;
                    """,
                    (file_type, file_id)
                )
                sustained_runs = cur.fetchone()[0]

            if sustained_runs > 0:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO alerts (file_id, severity, description) VALUES (%s, 'HIGH', %s)",
                        (file_id, f"Signal 3 — Pattern Consistency: {sustained_runs} sustained anomaly run(s) detected. Consistent with injected payload.")
                    )
                    cur.execute(
                        """
                        UPDATE files
                        SET threat_score = threat_score + 2,
                            risk_level   = CASE
                                WHEN threat_score + 2 >= 15 THEN 'FLAGGED'
                                WHEN threat_score + 2 >= 5  THEN 'SUSPICIOUS'
                                ELSE risk_level
                            END
                        WHERE file_id = %s
                        """,
                        (file_id,)
                    )
                    pg_conn.commit()

            #step 4: fetch the final status and alerts generated by DB triggers
            final_status = "PENDING"
            flagged_count = 0

            with pg_conn.cursor() as cur:
                cur.execute(
                    "SELECT status, alert_count FROM get_file_summary(%s)",
                    (file_id,)
                )
                row = cur.fetchone()
                if row:
                    final_status = row[0]
                    flagged_count = int(row[1] or 0)


            #step 4: extract threat payloads and send telemetry to MongoDB
            if flagged_count > 0:
                with pg_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT s.segment_index 
                        FROM alerts a 
                        JOIN segments s ON a.segment_id = s.segment_id 
                        WHERE a.file_id = %s
                        """, (file_id,)
                    )
                    alert_rows = cur.fetchall()
                    for alert_row in alert_rows:
                        seg_idx = alert_row[0]
                        # Find the raw bytes from segments array
                        for seg in segments:
                            if seg["segment_index"] == seg_idx:
                                payload_hex = seg["raw_bytes"].hex()
                                self.db.store_threat_payload(file_id, seg_idx, payload_hex)
                                break
            
            total_duration_ms = int((time.time() - scan_start_time) * 1000)
            self.db.insert_scan_telemetry({
                "file_id": file_id,
                "file_type": file_type,
                "file_size_bytes": os.path.getsize(file_path),
                "total_segments": len(segments),
                "analysis_duration_ms": analysis_duration_ms,
                "db_persist_duration_ms": db_duration_ms,
                "total_duration_ms": total_duration_ms,
                "flagged": (flagged_count > 0)
            })
            
            return ScanResult(
                file_id=file_id,
                total_segments=len(segments),
                alerts_raised=[], # api/main.py does not use this field in /upload response
                flagged_count=flagged_count,
                status=final_status,
            )

        except Exception as exc:
            #surface_the error cleanly; the db layer already rolled back postgres.
            return ScanResult(
                file_id=-1,
                total_segments=0,
                status="error",
                error=str(exc),
            )


if __name__ == "__main__":
    print("[lumenaid] scan_pipeline.py — import and instantiate ScanPipeline to use.")
    print("see commented usage block above for a wiring example.")
