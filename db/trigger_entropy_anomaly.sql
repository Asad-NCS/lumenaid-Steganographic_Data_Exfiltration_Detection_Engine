-- this file basically detects anomalies by creating a trigger that runs after every insert.

CREATE OR REPLACE FUNCTION fn_detect_entropy_anomalies()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    -- Holds one row per affected file after aggregation + join.
    r RECORD;
BEGIN
    FOR r IN
        SELECT
            -- ── Core identifiers ──────────────────────────────────────────────
            ins.file_id,
            f.file_type,

            -- ── Aggregated entropy for this batch ─────────────────────────────
            MAX(ins.entropy_score)                          AS max_entropy,

            -- ── Baseline thresholds for this file type ────────────────────────
            b.mean_entropy,
            b.threshold_sigma,
            (b.mean_entropy + 3.0 * b.threshold_sigma)       AS anomaly_threshold,

            (
                SELECT s2.segment_id
                FROM   segments s2
                WHERE  s2.file_id       = ins.file_id
                  AND  s2.segment_index = (
                           SELECT s3.segment_index
                           FROM   inserted_rows s3
                           WHERE  s3.file_id = ins.file_id
                           ORDER  BY s3.entropy_score DESC
                           LIMIT  1
                       )
                LIMIT  1
            )                                               AS worst_segment_id,

            -- ── Human-readable segment position for the alert description ──────
            (
                SELECT s4.segment_index
                FROM   inserted_rows s4
                WHERE  s4.file_id = ins.file_id
                ORDER  BY s4.entropy_score DESC
                LIMIT  1
            )                                               AS worst_segment_index,

            -- ── The raw entropy score of that worst segment ───────────────────
            (
                SELECT s5.entropy_score
                FROM   inserted_rows s5
                WHERE  s5.file_id = ins.file_id
                ORDER  BY s5.entropy_score DESC
                LIMIT  1
            )                                               AS worst_entropy_score

        -- `inserted_rows` is the transition table — only rows from THIS statement
        FROM       inserted_rows  ins
        JOIN       files          f   ON f.file_id   = ins.file_id
        JOIN       baselines      b   ON b.file_type = f.file_type
        GROUP BY   ins.file_id,
                   f.file_type,
                   b.mean_entropy,
                   b.threshold_sigma

    LOOP
        IF r.max_entropy > r.anomaly_threshold THEN

            INSERT INTO alerts (
                file_id,
                segment_id,
                severity,
                entropy_score,
                description
            )
            VALUES (
                r.file_id,

                r.worst_segment_id,     -- FK to the offending segment (nullable)

                CASE
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 1.0 THEN 'CRITICAL'
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 0.5 THEN 'HIGH'
                    ELSE                                                         'MEDIUM'
                END,

                r.worst_entropy_score,

                -- Human-readable description requested in the spec:
                'High Entropy Detected in Segment '
                    || r.worst_segment_index::TEXT
                    || ' (file_id='    || r.file_id::TEXT
                    || ', score='      || r.worst_entropy_score::TEXT
                    || ', threshold='  || r.anomaly_threshold::TEXT
                    || ', file_type='  || r.file_type
                    || ')'
            );

            -- Step 2: BONUS — stamp the parent file as FLAGGED.
            UPDATE files
            SET    status     = 'FLAGGED',
                   updated_at = NOW()
            WHERE  file_id = r.file_id;

        ELSE
            UPDATE files
            SET    status     = 'CLEAN',
                   updated_at = NOW()
            WHERE  file_id = r.file_id
              AND  status  <> 'FLAGGED';

        END IF;

    END LOOP;

    -- Statement-level trigger functions MUST return NULL.
    RETURN NULL;

END;
$$;


DROP TRIGGER IF EXISTS entropy_anomaly_trigger ON segments;

CREATE TRIGGER entropy_anomaly_trigger
    AFTER INSERT
    ON         segments
    REFERENCING NEW TABLE AS inserted_rows   -- transition table carrying the batch
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_detect_entropy_anomalies();