-- Procedure: refresh_threat_analytics
-- Purpose: Refreshes the materialized view asynchronously for the dashboard.
CREATE OR REPLACE PROCEDURE refresh_threat_analytics()
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_analytics;
    RAISE NOTICE 'Materialized view mv_threat_analytics refreshed successfully.';
END;
$$;


CREATE OR REPLACE PROCEDURE sp_recalculate_baselines(p_file_type VARCHAR)
LANGUAGE plpgsql
AS $$
DECLARE
    v_new_mean NUMERIC;
    v_new_sigma NUMERIC;
    v_avg_size BIGINT;
    v_count INTEGER;
BEGIN
    -- 1. Entropy Stats
    SELECT AVG(s.entropy_score), STDDEV(s.entropy_score), COUNT(*)
    INTO v_new_mean, v_new_sigma, v_count
    FROM segments s
    JOIN files f ON s.file_id = f.file_id
    WHERE f.file_type = p_file_type AND f.status = 'CLEAN';

    -- 2. File Size Stats
    SELECT AVG(file_size)
    INTO v_avg_size
    FROM files
    WHERE file_type = p_file_type AND status = 'CLEAN';

    IF v_count > 0 THEN
        UPDATE baselines 
        SET mean_entropy = v_new_mean,
            threshold_sigma = COALESCE(v_new_sigma, 0.2),
            avg_file_size = COALESCE(v_avg_size, 0),
            updated_at = NOW()
        WHERE file_type = p_file_type;
        
        RAISE NOTICE 'Multi-Signal Baseline Updated for %', p_file_type;
    ELSE
        RAISE NOTICE 'No clean data for %', p_file_type;
    END IF;
END;
$$;
