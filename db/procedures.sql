--Stored procedures — get_file_summary(), get_flagged_files(), update_baseline()

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
        (SELECT COUNT(*) FROM alerts WHERE file_id = p_file_id),
        f.file_name,
        f.file_type,
        f.submitted_at,
        (SELECT MAX(entropy_score) FROM segments WHERE file_id = p_file_id)
    FROM files f
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
        (SELECT COUNT(*) FROM alerts a WHERE a.file_id = f.file_id),
        (SELECT MAX(s.entropy_score) FROM segments s WHERE s.file_id = f.file_id)
    FROM files f
    WHERE f.status = 'FLAGGED'
    ORDER BY (SELECT MAX(s.entropy_score) FROM segments s WHERE s.file_id = f.file_id) DESC;
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
