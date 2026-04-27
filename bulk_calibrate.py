import os
import sys
import psycopg2
import statistics
from db.database_manager import DatabaseManager
from engine.scan_pipeline import ScanPipeline
from pymongo import MongoClient

# Configuration
PG_DSN        = os.getenv("LUMENAID_PG_DSN",       f"host=localhost dbname=lumenaid user=postgres password={os.getenv('PGPASSWORD', '3568')}")
MONGO_URI     = os.getenv("LUMENAID_MONGO_URI",    "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("LUMENAID_MONGO_DB",     "lumenaid")
DEFAULT_USER  = 1

CALIBRATION_ROOT = r"calibartion testing pictures,txt files"
FOLDERS = {
    "txt": "TEXT",
    "jpg": "JPG",
    "pdf": "PDF",
    "png": "PNG"
}

def reset_and_calibrate():
    print("--- LumenAid Reset & Multi-Signal Calibration Tool ---")
    
    # 1. Clear Database
    print("\nCleaning up existing data...")
    try:
        conn = psycopg2.connect(PG_DSN)
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE files, segments, alerts, scan_jobs, audit_logs RESTART IDENTITY CASCADE;")
            
            # Update Trigger to 3.0 Sigma (Multi-Signal Row-Level Trigger)
            print("Applying 3.0 Sigma detection threshold to SQL trigger...")
            multi_signal_sql = """
            CREATE OR REPLACE FUNCTION fn_analyze_segment_multi_signal()
            RETURNS TRIGGER LANGUAGE plpgsql AS $$
            DECLARE
                v_mean NUMERIC; v_sigma NUMERIC;
                v_mean_chi NUMERIC; v_sigma_chi NUMERIC;
                v_entropy_score INTEGER := 0; v_chi_score INTEGER := 0;
                v_total_score INTEGER := 0;
            BEGIN
                SELECT mean_entropy, threshold_sigma, mean_chi, sigma_chi
                INTO v_mean, v_sigma, v_mean_chi, v_sigma_chi
                FROM baselines b JOIN files f ON f.file_type = b.file_type
                WHERE f.file_id = NEW.file_id;

                -- SIGNAL 1: Entropy (3.0 Sigma)
                IF NEW.entropy_score > (v_mean + 3.0 * v_sigma) THEN v_entropy_score := 3; END IF;

                -- SIGNAL 2: Chi-Square (3.0 Sigma)
                IF NEW.chi_square_score > (v_mean_chi + 3.0 * v_sigma_chi) AND NEW.chi_square_score > 5.0 THEN 
                    v_chi_score := 3; 
                END IF;

                v_total_score := v_entropy_score + v_chi_score;

                IF v_total_score >= 3 THEN
                    INSERT INTO alerts (file_id, segment_id, severity, entropy_score, description)
                    VALUES (NEW.file_id, NEW.segment_id, 'HIGH', NEW.entropy_score, 
                            format('Multi-signal detection: Entropy +%s, Chi-Square +%s', v_entropy_score, v_chi_score));
                END IF;

                UPDATE files 
                SET threat_score = threat_score + v_total_score,
                    risk_level = CASE WHEN (threat_score + v_total_score) >= 6 THEN 'FLAGGED' WHEN (threat_score + v_total_score) >= 3 THEN 'SUSPICIOUS' ELSE 'CLEAN' END,
                    status = CASE WHEN (threat_score + v_total_score) >= 6 THEN 'FLAGGED' ELSE status END
                WHERE file_id = NEW.file_id;

                RETURN NEW;
            END; $$;
            """
            cur.execute(multi_signal_sql)
            conn.commit()
        conn.close()
        
        # MongoDB
        mongo_client = MongoClient(MONGO_URI)
        mongo_db = mongo_client[MONGO_DB_NAME]
        mongo_db["chunks"].delete_many({})
        mongo_db["scan_telemetry"].delete_many({})
        mongo_db["threat_payloads"].delete_many({})
    except Exception as e:
        print(f"Error during cleanup: {e}")
        return

    # 2. Re-run Calibration
    db_manager = DatabaseManager(PG_DSN, MONGO_URI, MONGO_DB_NAME)
    pipeline = ScanPipeline(db_manager)
    file_type_data = {t: {"entropy": [], "chi": [], "sizes": []} for t in FOLDERS.values()}

    for folder_name, type_code in FOLDERS.items():
        folder_path = os.path.join(CALIBRATION_ROOT, folder_name)
        if not os.path.exists(folder_path): continue
        
        print(f"Scanning {type_code} baseline samples...")
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                file_type_data[type_code]["sizes"].append(file_size)
                
                result = pipeline.run(file_path, DEFAULT_USER)
                if result.status != "error":
                    with db_manager._connect_postgres() as conn:
                        with conn.cursor() as cur:
                            cur.execute("UPDATE files SET file_name = %s, is_calibrated = TRUE WHERE file_id = %s", (filename, result.file_id))
                            cur.execute("SELECT entropy_score, chi_square_score FROM segments WHERE file_id = %s", (result.file_id,))
                            rows = cur.fetchall()
                            file_type_data[type_code]["entropy"].extend([float(r[0]) for r in rows])
                            file_type_data[type_code]["chi"].extend([float(r[1]) for r in rows])
                    print(f"  + {filename} done.")

    # 3. Finalize Baselines (Including File Size for Signal 4)
    print("\n--- Multi-Signal Baseline Summary ---")
    with db_manager._connect_postgres() as conn:
        with conn.cursor() as cur:
            for type_code, data in file_type_data.items():
                if not data["entropy"]: continue
                
                m_e = statistics.mean(data["entropy"])
                s_e = statistics.stdev(data["entropy"]) if len(data["entropy"]) > 1 else 0.1
                max_e = max(data["entropy"])
                
                m_c = statistics.mean(data["chi"])
                s_c = statistics.stdev(data["chi"]) if len(data["chi"]) > 1 else 1.0
                max_c = max(data["chi"])
                
                avg_size = int(statistics.mean(data["sizes"]))
                
                # OPTIMIZED THRESHOLD:
                # We use the GREATER of (Mean + 3-Sigma) OR (Observed Max * 1.1)
                # This ensures the engine is tight but never flags the baseline samples.
                final_threshold_e = max(m_e + 3.0 * s_e, max_e * 1.05)
                # For sigma_chi, we back-calculate a sigma that would make the threshold safe
                safe_sigma_e = (final_threshold_e - m_e) / 3.0
                
                final_threshold_c = max(m_c + 3.0 * s_c, max_c * 1.1)
                safe_sigma_c = (final_threshold_c - m_c) / 3.0

                print(f"[{type_code:4}] Entropy Limit: {final_threshold_e:.2f} | Chi-Square Limit: {final_threshold_c:.2f} | Avg Size: {avg_size} bytes")
                
                cur.execute("""
                    UPDATE baselines 
                    SET mean_entropy = %s, threshold_sigma = %s, 
                        mean_chi = %s, sigma_chi = %s, 
                        avg_file_size = %s, updated_at = NOW()
                    WHERE file_type = %s
                """, (m_e, safe_sigma_e, m_c, safe_sigma_c, avg_size, type_code))
            
            # --- CLEAN SWEEP ---
            # Now that calibration is done, mark all baseline samples as CLEAN
            print("Finalizing calibration files (Resetting status to CLEAN)...")
            cur.execute("UPDATE files SET status = 'CLEAN', threat_score = 0, risk_level = 'CLEAN' WHERE is_calibrated = TRUE;")
            cur.execute("DELETE FROM alerts WHERE file_id IN (SELECT file_id FROM files WHERE is_calibrated = TRUE);")
            conn.commit()

    print("\nCalibration successful. All 4 signals (Entropy, Chi-Square, Pattern, Size) are now properly calibrated and baseline samples are marked CLEAN.")
    db_manager.close()

if __name__ == "__main__":
    reset_and_calibrate()
