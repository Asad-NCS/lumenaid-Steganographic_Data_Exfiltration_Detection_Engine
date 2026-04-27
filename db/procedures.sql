--stored procedures for lumenaid

CREATE OR REPLACE FUNCTION get_file_summary(p_file_id INTEGER)
RETURNS TABLE (
    status           VARCHAR(20),
    alert_count      BIGINT,
    file_name        VARCHAR(512),
    file_type        VARCHAR(20),
    submitted_at     TIMESTAMPTZ,
    max_entropy      NUMERIC(6,4)
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        f.status,
        COUNT(a.alert_id),
        f.file_name,
        f.file_type,
        f.submitted_at,
        MAX(s.entropy_score)
    FROM files f
    LEFT JOIN alerts   a ON a.file_id = f.file_id
    LEFT JOIN segments s ON s.file_id = f.file_id
    WHERE f.file_id = p_file_id
    GROUP BY f.file_id, f.status, f.file_name, f.file_type, f.submitted_at;
END;
$$;


CREATE OR REPLACE FUNCTION get_flagged_files()
RETURNS TABLE (
    file_id          INTEGER,
    file_name        VARCHAR(512),
    file_type        VARCHAR(20),
    submitted_at     TIMESTAMPTZ,
    alert_count      BIGINT,
    max_entropy      NUMERIC(6,4)
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        f.file_id,
        f.file_name,
        f.file_type,
        f.submitted_at,
        COUNT(a.alert_id),
        MAX(s.entropy_score)
    FROM files f
    LEFT JOIN alerts   a ON a.file_id = f.file_id
    LEFT JOIN segments s ON s.file_id = f.file_id
    WHERE f.status = 'FLAGGED'
    GROUP BY f.file_id, f.file_name, f.file_type, f.submitted_at
    ORDER BY MAX(s.entropy_score) DESC;
END;
$$;


CREATE OR REPLACE FUNCTION update_baseline(
    p_file_type       VARCHAR(20),
    p_mean_entropy    NUMERIC(6,4),
    p_threshold_sigma NUMERIC(6,4)
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE baselines
    SET mean_entropy    = p_mean_entropy,
        threshold_sigma = p_threshold_sigma,
        updated_at      = NOW()
    WHERE file_type = p_file_type;
END;
$$;