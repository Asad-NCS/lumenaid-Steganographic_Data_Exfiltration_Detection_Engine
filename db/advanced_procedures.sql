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


-- Procedure: sp_recalculate_baselines
-- Purpose: Dynamically recalculate file type baselines using a Cursor.
-- Memory-safe processing for millions of segments.
CREATE OR REPLACE PROCEDURE sp_recalculate_baselines(p_file_type VARCHAR)
LANGUAGE plpgsql
AS $$
DECLARE
    -- Cursor to iterate over chunks without loading all into RAM
    seg_cursor CURSOR FOR 
        SELECT s.entropy_score 
        FROM segments s
        JOIN files f ON s.file_id = f.file_id
        WHERE f.file_type = p_file_type AND f.status = 'CLEAN';
    
    v_entropy NUMERIC;
    v_total_entropy NUMERIC := 0;
    v_count INTEGER := 0;
    v_new_mean NUMERIC;
BEGIN
    OPEN seg_cursor;
    
    LOOP
        FETCH seg_cursor INTO v_entropy;
        EXIT WHEN NOT FOUND;
        
        v_total_entropy := v_total_entropy + v_entropy;
        v_count := v_count + 1;
    END LOOP;
    
    CLOSE seg_cursor;
    
    IF v_count > 0 THEN
        v_new_mean := v_total_entropy / v_count;
        
        UPDATE baselines 
        SET mean_entropy = v_new_mean,
            updated_at = NOW()
        WHERE file_type = p_file_type;
        
        RAISE NOTICE 'Adaptive Baseline Triggered: Updated % mean to %', p_file_type, v_new_mean;
    ELSE
        RAISE NOTICE 'No clean files found for %', p_file_type;
    END IF;
END;
$$;
