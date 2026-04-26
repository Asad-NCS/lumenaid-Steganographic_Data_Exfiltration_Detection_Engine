import psycopg2
import os

PG_DSN = "host=localhost dbname=lumenaid user=postgres password=3568"

SQL = """
-- 1. Schema Upgrades
ALTER TABLE baselines ADD COLUMN IF NOT EXISTS avg_file_size BIGINT DEFAULT 0;
ALTER TABLE baselines ADD COLUMN IF NOT EXISTS expected_distribution JSONB DEFAULT '{}';
ALTER TABLE files ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0;
ALTER TABLE files ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20) DEFAULT 'CLEAN';
ALTER TABLE segments ADD COLUMN IF NOT EXISTS chi_square_score NUMERIC(10,4) DEFAULT 0;

-- 2. Updated Trigger Function (The Brain)
CREATE OR REPLACE FUNCTION fn_analyze_segment_multi_signal()
RETURNS TRIGGER AS $$
DECLARE
    v_mean NUMERIC;
    v_sigma NUMERIC;
    v_total_score INTEGER := 0;
    v_entropy_score INTEGER := 0;
    v_chi_score INTEGER := 0;
BEGIN
    -- Fetch baseline for this file type
    SELECT mean_entropy, threshold_sigma 
    INTO v_mean, v_sigma
    FROM baselines b
    JOIN files f ON f.file_type = b.file_type
    WHERE f.file_id = NEW.file_id;

    -- SIGNAL 1: Shannon Entropy (Weight: 3)
    -- If entropy > mean + 1.5 sigma -> Suspect
    IF NEW.entropy_score > (v_mean + 1.5 * v_sigma) THEN
        v_entropy_score := 3;
    END IF;

    -- SIGNAL 2: Chi-Square Score (Weight: 3)
    -- Higher Chi-Square = Worse fit to natural DNA
    -- Threshold 50.0 is a heuristic for now, will be calibrated
    IF NEW.chi_square_score > 50.0 THEN
        v_chi_score := 3;
    END IF;

    -- Combine Scores
    v_total_score := v_entropy_score + v_chi_score;

    -- If score is high, raise an alert
    IF v_total_score >= 3 THEN
        INSERT INTO alerts (file_id, severity, description)
        VALUES (
            NEW.file_id,
            CASE WHEN v_total_score >= 6 THEN 'HIGH' ELSE 'MEDIUM' END,
            format('Multi-signal detection: Entropy Score %s, Chi-Square Score %s', v_entropy_score, v_chi_score)
        );
    END IF;

    -- Update File Risk Level (Running update)
    UPDATE files 
    SET threat_score = threat_score + v_total_score,
        risk_level = CASE 
            WHEN (threat_score + v_total_score) >= 6 THEN 'FLAGGED'
            WHEN (threat_score + v_total_score) >= 3 THEN 'SUSPICIOUS'
            ELSE 'CLEAN'
        END,
        status = CASE 
            WHEN (threat_score + v_total_score) >= 6 THEN 'FLAGGED'
            ELSE status
        END
    WHERE file_id = NEW.file_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 3. Replace old trigger
DROP TRIGGER IF EXISTS tg_analyze_segment ON segments;
CREATE TRIGGER tg_analyze_segment
AFTER INSERT ON segments
FOR EACH ROW
EXECUTE FUNCTION fn_analyze_segment_multi_signal();

-- 4. Extend Analytics View
DROP MATERIALIZED VIEW IF EXISTS mv_threat_analytics;
CREATE MATERIALIZED VIEW mv_threat_analytics AS
SELECT 
    f.file_type,
    COUNT(*) as total_files,
    AVG(f.threat_score) as avg_threat_score,
    MAX(f.threat_score) as max_threat_score,
    AVG(s.chi_square_score) as avg_chi_square,
    COUNT(a.alert_id) as total_alerts
FROM files f
LEFT JOIN segments s ON f.file_id = s.file_id
LEFT JOIN alerts a ON f.file_id = a.file_id
GROUP BY f.file_type;

CREATE OR REPLACE VIEW vw_smoothed_anomalies AS
SELECT
    s.file_id,
    s.segment_index,
    s.entropy_score,
    COALESCE(s.chi_square_score, 0)                              AS chi_square_score,
    AVG(s.entropy_score) OVER (
        PARTITION BY s.file_id
        ORDER BY s.segment_index
        ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING
    )                                                            AS smoothed_entropy,
    b.mean_entropy,
    (b.mean_entropy + b.threshold_sigma)                         AS anomaly_threshold,
    ROUND(
        AVG(s.entropy_score) OVER (
            PARTITION BY s.file_id
            ORDER BY s.segment_index
            ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING
        ) - b.mean_entropy,
        4
    )                                                            AS deviation,
    CASE
        WHEN AVG(s.entropy_score) OVER (
            PARTITION BY s.file_id
            ORDER BY s.segment_index
            ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING
        ) > (b.mean_entropy + b.threshold_sigma)
        THEN TRUE
        ELSE FALSE
    END                                                          AS is_anomalous,
    CASE
        WHEN s.entropy_score > (b.mean_entropy + (1.5 * b.threshold_sigma)) THEN 3
        ELSE 0
    END                                                          AS entropy_signal_score,
    CASE
        WHEN COALESCE(s.chi_square_score, 0) > 50.0 THEN 3
        ELSE 0
    END                                                          AS chi_signal_score,
    (
        CASE
            WHEN s.entropy_score > (b.mean_entropy + (1.5 * b.threshold_sigma)) THEN 3
            ELSE 0
        END
        +
        CASE
            WHEN COALESCE(s.chi_square_score, 0) > 50.0 THEN 3
            ELSE 0
        END
    )                                                            AS segment_score_contribution,
    COALESCE(f.threat_score, 0)                                  AS file_threat_score,
    f.risk_level
FROM segments  s
JOIN files     f ON f.file_id   = s.file_id
JOIN baselines b ON b.file_type = f.file_type;
"""

try:
    conn = psycopg2.connect(PG_DSN)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(SQL)
    print("Database Migration Successful!")
except Exception as e:
    print(f"Migration Failed: {e}")
finally:
    if conn: conn.close()
