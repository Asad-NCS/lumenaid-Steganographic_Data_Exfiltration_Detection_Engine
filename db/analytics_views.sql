--this file contains views and materialized views for analytics

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
    (b.mean_entropy + 3.0 * b.threshold_sigma)                    AS anomaly_threshold,
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
        ) > (b.mean_entropy + 3.0 * b.threshold_sigma)
        THEN TRUE
        ELSE FALSE
    END                                                          AS is_anomalous,
    CASE
        WHEN s.entropy_score > (b.mean_entropy + 3.0 * b.threshold_sigma) THEN 3
        ELSE 0
    END                                                          AS entropy_signal_score,
    CASE
        WHEN COALESCE(s.chi_square_score, 0) > (COALESCE(b.mean_chi,0) + 3.0 * COALESCE(b.sigma_chi,0)) THEN 3
        ELSE 0
    END                                                          AS chi_signal_score,
    (
        CASE
            WHEN s.entropy_score > (b.mean_entropy + 3.0 * b.threshold_sigma) THEN 3
            ELSE 0
        END
        +
        CASE
            WHEN COALESCE(s.chi_square_score, 0) > (COALESCE(b.mean_chi,0) + 3.0 * COALESCE(b.sigma_chi,0)) THEN 3
            ELSE 0
        END
    )                                                    AS segment_score_contribution,
    COALESCE(f.threat_score, 0)                          AS file_threat_score,
    f.risk_level
FROM segments  s
JOIN files     f ON f.file_id   = s.file_id
JOIN baselines b ON b.file_type = f.file_type;


CREATE MATERIALIZED VIEW IF NOT EXISTS mv_threat_analytics AS
SELECT
    f.file_type,
    COUNT(f.file_id)                                              AS total_files_scanned,
    SUM(CASE WHEN f.status = 'FLAGGED' THEN 1 ELSE 0 END)        AS total_threats,
    AVG(s.max_entropy)                                            AS avg_max_entropy,
    b.mean_entropy                                                AS baseline_mean,
    MAX(f.submitted_at)                                           AS last_scan_time
FROM files f
JOIN baselines b ON f.file_type = b.file_type
LEFT JOIN (
    SELECT file_id, MAX(entropy_score) AS max_entropy
    FROM   segments
    GROUP  BY file_id
) s ON f.file_id = s.file_id
GROUP BY f.file_type, b.mean_entropy;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_threat_analytics_type ON mv_threat_analytics(file_type);