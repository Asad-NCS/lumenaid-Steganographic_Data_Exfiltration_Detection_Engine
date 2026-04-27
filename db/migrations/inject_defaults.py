import psycopg2
import os

PG_DSN = f"host=localhost dbname=lumenaid user=postgres password={os.getenv('PGPASSWORD', '3568')}"

SQL = """
-- Set initial 'DNA' and Size baselines for the Multi-Signal engine
UPDATE baselines SET 
    avg_file_size = 51200, -- 50KB default
    threshold_sigma = 0.5
WHERE file_type = 'TEXT';

UPDATE baselines SET 
    avg_file_size = 256000, -- 250KB default
    threshold_sigma = 0.2
WHERE file_type = 'JPG';

UPDATE baselines SET 
    avg_file_size = 307200, -- 300KB default
    threshold_sigma = 0.2
WHERE file_type = 'PNG';

UPDATE baselines SET 
    avg_file_size = 1048576, -- 1MB default
    threshold_sigma = 0.3
WHERE file_type = 'PDF';

RAISE NOTICE 'Multi-Signal Baseline Defaults Injected.';
"""

try:
    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("UPDATE baselines SET avg_file_size = 51200 WHERE file_type = 'TEXT';")
        cur.execute("UPDATE baselines SET avg_file_size = 256000 WHERE file_type = 'JPG';")
        cur.execute("UPDATE baselines SET avg_file_size = 307200 WHERE file_type = 'PNG';")
        cur.execute("UPDATE baselines SET avg_file_size = 1048576 WHERE file_type = 'PDF';")
    print("Baseline Defaults Injected Successfully!")
except Exception as e:
    print(f"Injection Failed: {e}")
finally:
    if conn: conn.close()
