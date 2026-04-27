import os
import psycopg2

def update_trigger():
    conn = psycopg2.connect(f'host=localhost dbname=lumenaid user=postgres password={os.getenv("PGPASSWORD", "3568")}')
    cur = conn.cursor()
    
    sql = """
    CREATE OR REPLACE FUNCTION fn_finalize_file_threat()
    RETURNS TRIGGER AS $$
    DECLARE
        v_avg_size BIGINT;
    BEGIN
        -- Trigger only when status moves to CLEAN or FLAGGED
        IF NEW.status != OLD.status AND NEW.status IN ('CLEAN', 'FLAGGED') THEN
            -- Compare only against the CALIBRATED reference samples
            SELECT AVG(file_size) INTO v_avg_size 
            FROM files 
            WHERE file_type = NEW.file_type AND is_calibrated = TRUE;
    

        IF v_avg_size > 0 AND NEW.file_size > (v_avg_size * 1.2) THEN
            INSERT INTO alerts (file_id, severity, description)
            VALUES (
                NEW.file_id, 'LOW',
                format('Signal 4 — File size anomaly: %s bytes vs calibrated avg %s bytes', NEW.file_size, v_avg_size)
            );
            END IF;
        END IF;

        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    cur.execute(sql)
    conn.commit()
    cur.close()
    conn.close()
    print("Signal 4 Logic Perfected.")

if __name__ == "__main__":
    update_trigger()
