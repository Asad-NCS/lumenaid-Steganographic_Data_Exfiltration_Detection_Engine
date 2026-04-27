-- this file basically detects anomalies by creating a trigger that runs after every insert.

CREATE OR REPLACE FUNCTION fn_detect_entropy_anomalies()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT
            ins.file_id,
            f.file_type,
            MAX(ins.entropy_score)                          AS max_entropy,
            MAX(ins.chi_square_score)                       AS max_chi,
            b.mean_entropy,
            b.threshold_sigma,
            b.mean_chi,
            b.sigma_chi,
            (b.mean_entropy + 3.0 * b.threshold_sigma)     AS entropy_threshold,
            (COALESCE(b.mean_chi, 0) + 3.0 * COALESCE(b.sigma_chi, 1)) AS chi_threshold,
            (
                SELECT s2.segment_id FROM segments s2
                WHERE s2.file_id = ins.file_id
                  AND s2.segment_index = (
                      SELECT s3.segment_index FROM inserted_rows s3
                      WHERE s3.file_id = ins.file_id
                      ORDER BY GREATEST(s3.entropy_score, s3.chi_square_score/1000.0) DESC LIMIT 1
                  )
                LIMIT 1
            )                                               AS worst_segment_id,
            (
                SELECT s4.segment_index FROM inserted_rows s4
                WHERE s4.file_id = ins.file_id
                ORDER BY GREATEST(s4.entropy_score, s4.chi_square_score/1000.0) DESC LIMIT 1
            )                                               AS worst_segment_index,
            (
                SELECT s5.entropy_score FROM inserted_rows s5
                WHERE s5.file_id = ins.file_id
                ORDER BY GREATEST(s5.entropy_score, s5.chi_square_score/1000.0) DESC LIMIT 1
            )                                               AS worst_entropy,
            (
                SELECT s6.chi_square_score FROM inserted_rows s6
                WHERE s6.file_id = ins.file_id
                ORDER BY GREATEST(s6.entropy_score, s6.chi_square_score/1000.0) DESC LIMIT 1
            )                                               AS worst_chi
        FROM inserted_rows ins
        JOIN files     f ON f.file_id   = ins.file_id
        JOIN baselines b ON b.file_type = f.file_type
        GROUP BY ins.file_id, f.file_type, b.mean_entropy, b.threshold_sigma, b.mean_chi, b.sigma_chi
    LOOP
        -- If EITHER Entropy OR Chi-Square exceeds 3-sigma
        IF r.max_entropy > r.entropy_threshold OR (r.max_chi > r.chi_threshold AND r.max_chi > 5.0) THEN
            
            INSERT INTO alerts (file_id, segment_id, severity, entropy_score, description)
            VALUES (
                r.file_id, r.worst_segment_id,
                'HIGH',
                r.worst_entropy,
                format('Anomaly in segment %s. Entropy: %s (limit %s), Chi-Square: %s (limit %s)', 
                       r.worst_segment_index, round(r.worst_entropy, 2), round(r.entropy_threshold, 2), 
                       round(r.worst_chi, 2), round(r.chi_threshold, 2))
            );

            UPDATE files
            SET    status     = 'FLAGGED',
                   threat_score = threat_score + 5,
                   updated_at = NOW()
            WHERE  file_id = r.file_id;
        ELSE
            -- Only downgrade to CLEAN if NO other signals have flagged it yet
            UPDATE files
            SET    status     = 'CLEAN',
                   updated_at = NOW()
            WHERE  file_id    = r.file_id
              AND  status     = 'PENDING'
              AND  threat_score = 0;
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS entropy_anomaly_trigger ON segments;
CREATE TRIGGER entropy_anomaly_trigger
    AFTER INSERT ON segments
    REFERENCING NEW TABLE AS inserted_rows
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_detect_entropy_anomalies();