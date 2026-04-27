--this file is to create tables and trigger for the database

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS file_type_registry (
    type_code       VARCHAR(20)  PRIMARY KEY,
    description     TEXT         NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    user_id         SERIAL       PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50)  NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'analyst', 'readonly')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS files (
    file_id         SERIAL       PRIMARY KEY,
    user_id         INTEGER      NOT NULL
                        REFERENCES users(user_id) ON DELETE CASCADE,
    file_name       VARCHAR(512),
    file_type       VARCHAR(20)  NOT NULL
                        REFERENCES file_type_registry(type_code),
    file_size       BIGINT       NOT NULL DEFAULT 0,
    status          VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING', 'SCANNING', 'CLEAN', 'FLAGGED', 'ERROR')),
    threat_score    INTEGER      NOT NULL DEFAULT 0,
    risk_level      VARCHAR(20)  NOT NULL DEFAULT 'CLEAN',
    submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_user_id   ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_status    ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_file_type ON files(file_type);

CREATE TABLE IF NOT EXISTS segments (
    segment_id       SERIAL        PRIMARY KEY,
    file_id          INTEGER       NOT NULL
                         REFERENCES files(file_id) ON DELETE CASCADE,
    segment_index    INTEGER       NOT NULL
                         CHECK (segment_index >= 0),
    entropy_score    NUMERIC(6,4)  NOT NULL
                         CHECK (entropy_score >= 0 AND entropy_score <= 8),
    chi_square_score NUMERIC(10,4) NOT NULL DEFAULT 0,
    raw_chunk_ref    VARCHAR(24)   NOT NULL,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    UNIQUE (file_id, segment_index)
);

CREATE INDEX IF NOT EXISTS idx_segments_file_id       ON segments(file_id);
CREATE INDEX IF NOT EXISTS idx_segments_entropy_score ON segments(entropy_score);

CREATE TABLE IF NOT EXISTS baselines (
    baseline_id           SERIAL       PRIMARY KEY,
    file_type             VARCHAR(20)  NOT NULL UNIQUE
                              REFERENCES file_type_registry(type_code),
    mean_entropy          NUMERIC(6,4) NOT NULL
                              CHECK (mean_entropy >= 0 AND mean_entropy <= 8),
    threshold_sigma       NUMERIC(6,4) NOT NULL
                              CHECK (threshold_sigma > 0),
    avg_file_size         BIGINT       NOT NULL DEFAULT 0,
    expected_distribution JSONB        NOT NULL DEFAULT '{}',
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        SERIAL       PRIMARY KEY,
    file_id         INTEGER      NOT NULL
                        REFERENCES files(file_id) ON DELETE CASCADE,
    segment_id      INTEGER
                        REFERENCES segments(segment_id) ON DELETE SET NULL,
    severity        VARCHAR(20)  NOT NULL DEFAULT 'HIGH'
                        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    entropy_score   NUMERIC(6,4),
    description     TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_file_id  ON alerts(file_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id           SERIAL       PRIMARY KEY,
    file_id          INTEGER      NOT NULL
                         REFERENCES files(file_id) ON DELETE CASCADE,
    job_status       VARCHAR(20)  NOT NULL DEFAULT 'QUEUED'
                         CHECK (job_status IN ('QUEUED', 'RUNNING', 'DONE', 'FAILED')),
    worker_id        VARCHAR(255),
    queued_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    max_entropy      NUMERIC(6,4),
    mean_entropy     NUMERIC(6,4),
    segments_scanned INTEGER,
    anomalies_found  INTEGER      DEFAULT 0,
    completed_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_file_id    ON scan_jobs(file_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_job_status ON scan_jobs(job_status);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          SERIAL       PRIMARY KEY,
    user_id         INTEGER
                        REFERENCES users(user_id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    payload         JSONB        NOT NULL DEFAULT '{}',
    logged_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id   ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action    ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_logged_at ON audit_logs(logged_at DESC);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'analyst_role') THEN
        CREATE ROLE analyst_role;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'admin_role') THEN
        CREATE ROLE admin_role;
    END IF;
END
$$;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO analyst_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO admin_role;

ALTER TABLE files ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_policies WHERE tablename='files' AND policyname='analyst_files_policy') THEN
        CREATE POLICY analyst_files_policy ON files FOR SELECT TO analyst_role
            USING (user_id = current_setting('app.current_user_id', true)::integer);
    END IF;
    IF NOT EXISTS (SELECT FROM pg_policies WHERE tablename='files' AND policyname='admin_files_policy') THEN
        CREATE POLICY admin_files_policy ON files FOR SELECT TO admin_role USING (true);
    END IF;
    IF NOT EXISTS (SELECT FROM pg_policies WHERE tablename='alerts' AND policyname='analyst_alerts_policy') THEN
        CREATE POLICY analyst_alerts_policy ON alerts FOR SELECT TO analyst_role
            USING (file_id IN (
                SELECT file_id FROM files
                WHERE user_id = current_setting('app.current_user_id', true)::integer
            ));
    END IF;
    IF NOT EXISTS (SELECT FROM pg_policies WHERE tablename='alerts' AND policyname='admin_alerts_policy') THEN
        CREATE POLICY admin_alerts_policy ON alerts FOR SELECT TO admin_role USING (true);
    END IF;
END
$$;

-- Signal 4: file size delta trigger
CREATE OR REPLACE FUNCTION fn_finalize_file_threat()
RETURNS TRIGGER AS $$
DECLARE
    v_avg_size BIGINT;
BEGIN
    IF NEW.status != OLD.status AND NEW.status IN ('CLEAN', 'FLAGGED') THEN
        SELECT avg_file_size INTO v_avg_size
        FROM baselines WHERE file_type = NEW.file_type;

        IF v_avg_size > 0 AND NEW.file_size > (v_avg_size * 1.2) THEN
            INSERT INTO alerts (file_id, severity, description)
            VALUES (
                NEW.file_id, 'LOW',
                format('Signal 4 — File size anomaly: %s bytes vs avg %s bytes', NEW.file_size, v_avg_size)
            );
            UPDATE files SET threat_score = threat_score + 2 WHERE file_id = NEW.file_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tg_finalize_file ON files;
CREATE TRIGGER tg_finalize_file
    AFTER UPDATE ON files
    FOR EACH ROW
    WHEN (OLD.status = 'PENDING' AND NEW.status != 'PENDING')
    EXECUTE FUNCTION fn_finalize_file_threat();

-- Remove duplicate row-level trigger if it exists
DROP TRIGGER IF EXISTS tg_analyze_segment ON segments;

-- Main entropy anomaly detection (statement-level — the correct approach)
DROP TRIGGER IF EXISTS entropy_anomaly_trigger ON segments;

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
            b.mean_entropy,
            b.threshold_sigma,
            (b.mean_entropy + 3.0 * b.threshold_sigma)            AS anomaly_threshold,
            (
                SELECT s2.segment_id FROM segments s2
                WHERE s2.file_id = ins.file_id
                  AND s2.segment_index = (
                      SELECT s3.segment_index FROM inserted_rows s3
                      WHERE s3.file_id = ins.file_id
                      ORDER BY s3.entropy_score DESC LIMIT 1
                  )
                LIMIT 1
            )                                               AS worst_segment_id,
            (
                SELECT s4.segment_index FROM inserted_rows s4
                WHERE s4.file_id = ins.file_id
                ORDER BY s4.entropy_score DESC LIMIT 1
            )                                               AS worst_segment_index,
            (
                SELECT s5.entropy_score FROM inserted_rows s5
                WHERE s5.file_id = ins.file_id
                ORDER BY s5.entropy_score DESC LIMIT 1
            )                                               AS worst_entropy_score
        FROM inserted_rows ins
        JOIN files     f ON f.file_id   = ins.file_id
        JOIN baselines b ON b.file_type = f.file_type
        GROUP BY ins.file_id, f.file_type, b.mean_entropy, b.threshold_sigma
    LOOP
        IF r.max_entropy > r.anomaly_threshold THEN
            INSERT INTO alerts (file_id, segment_id, severity, entropy_score, description)
            VALUES (
                r.file_id, r.worst_segment_id,
                CASE
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 1.0 THEN 'CRITICAL'
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 0.5 THEN 'HIGH'
                    ELSE 'MEDIUM'
                END,
                r.worst_entropy_score,
                'High Entropy Detected in Segment '
                    || r.worst_segment_index::TEXT
                    || ' (file_id='   || r.file_id::TEXT
                    || ', score='     || r.worst_entropy_score::TEXT
                    || ', threshold=' || r.anomaly_threshold::TEXT
                    || ', type='      || r.file_type || ')'
            );

            UPDATE files
            SET    threat_score = threat_score + 3,
                    status       = CASE
                        WHEN (threat_score + 3) >= 6 THEN 'FLAGGED'
                        WHEN (threat_score + 3) >= 3 THEN 'FLAGGED'
                        ELSE 'CLEAN'
                    END,
                    risk_level   = CASE
                        WHEN (threat_score + 3) >= 6 THEN 'FLAGGED'
                        WHEN (threat_score + 3) >= 3 THEN 'SUSPICIOUS'
                        ELSE 'CLEAN'
                    END,
                    updated_at   = NOW()
            WHERE  file_id = r.file_id;

        ELSE
            UPDATE files
            SET    status     = 'CLEAN',
                   risk_level = 'CLEAN',
                   updated_at = NOW()
            WHERE  file_id    = r.file_id
              AND  status    <> 'FLAGGED';
        END IF;
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE TRIGGER entropy_anomaly_trigger
    AFTER INSERT ON segments
    REFERENCING NEW TABLE AS inserted_rows
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_detect_entropy_anomalies();