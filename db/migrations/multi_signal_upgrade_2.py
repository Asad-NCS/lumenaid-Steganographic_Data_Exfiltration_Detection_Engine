import psycopg2
PG_DSN = "host=localhost dbname=lumenaid user=postgres password=3568"

SQL = """
ALTER TABLE files ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0;

-- Update the finalize function to check for size delta
CREATE OR REPLACE FUNCTION fn_finalize_file_threat()
RETURNS TRIGGER AS $$
DECLARE
    v_avg_size BIGINT;
    v_size_score INTEGER := 0;
BEGIN
    IF NEW.status != OLD.status AND NEW.status IN ('CLEAN', 'FLAGGED') THEN
        -- Get average size for this file type
        SELECT avg_file_size INTO v_avg_size 
        FROM baselines 
        WHERE file_type = NEW.file_type;

        -- SIGNAL 4: File Size Delta (Weight: 2)
        -- If file is > 20% larger than average, add 2 points
        IF v_avg_size > 0 AND NEW.file_size > (v_avg_size * 1.2) THEN
            v_size_score := 2;
            
            INSERT INTO alerts (file_id, severity, description)
            VALUES (NEW.file_id, 'LOW', format('File size anomaly: %s bytes vs avg %s bytes', NEW.file_size, v_avg_size));
            
            UPDATE files SET threat_score = threat_score + v_size_score WHERE file_id = NEW.file_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tg_finalize_file ON files;
CREATE TRIGGER tg_finalize_file
AFTER UPDATE ON files
FOR EACH ROW
WHEN (OLD.status = 'PENDING' AND NEW.status != 'PENDING')
EXECUTE FUNCTION fn_finalize_file_threat();
"""

try:
    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SQL)
    print("Database Migration Successful (Phase 1.5)!")
except Exception as e:
    print(f"Migration Failed: {e}")
finally:
    if conn: conn.close()
