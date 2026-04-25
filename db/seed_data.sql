-- this file is used to insert data into the tables 
INSERT INTO file_type_registry (type_code, description)
VALUES
    ('TEXT', 'Plain-text files (.txt, .csv, .log) — low, repetitive entropy'),
    ('PDF',  'Portable Document Format — moderate entropy due to compression'),
    ('JPG',  'JPEG image — high entropy baseline from lossy DCT compression'),
    ('PNG',  'PNG image — high entropy from lossless DEFLATE compression'),
    ('DOCX', 'Microsoft Word Open XML — moderate entropy, zip-compressed XML'),
    ('XLSX', 'Microsoft Excel Open XML — moderate entropy, zip-compressed XML'),
    ('ZIP',  'Generic ZIP archive — very high entropy, fully compressed'),
    ('MP3',  'MP3 audio — high entropy from perceptual audio compression'),
    ('EXE',  'Windows PE executable — variable, often high entropy'),
    ('BIN',  'Generic binary blob — entropy varies; used as catch-all type')
ON CONFLICT (type_code) DO UPDATE
    SET description = EXCLUDED.description;


-- 2. baselines
--    Realistic entropy statistics derived from empirical corpus analysis.
--
--    Interpretation of threshold_sigma:
--      A segment is anomalous when:
--        entropy_score > mean_entropy + threshold_sigma
--
--    Tuning notes per type:
--      TEXT  — very organised/repetitive content.  Wide sigma (0.5) because
--              natural language entropy varies a lot (code vs. prose).
--      PDF   — compressed but structured.  Tight sigma (0.3) because a
--              legitimate PDF stream is consistently ~7.2 bits/byte.
--      JPG   — JPEG entropy is already near-maximum (7.7). Ultra-tight sigma
--              (0.1) means even 7.8 triggers an alert — steganography tools
--              that pad high-frequency coefficients cause exactly this spike.
--      PNG   — DEFLATE output is high entropy but slightly lower than JPEG.
--      DOCX  — zipped XML; moderate and fairly consistent.
--      XLSX  — similar to DOCX.
--      ZIP   — pure compression output; near theoretical max, very tight sigma.
--      MP3   — perceptual compression produces reliably high entropy.
--      EXE   — wider sigma because packed vs. unpacked PE entropy differs a lot.
--      BIN   — broadest sigma; unknown binary format, be more permissive.
-- ---------------------------------------------------------------------------
INSERT INTO baselines (file_type, mean_entropy, threshold_sigma)
VALUES
    --  type    mean    sigma   (anomaly threshold = mean + sigma)
    ('TEXT',   4.4000, 0.5000),   -- threshold ≈ 4.90 bits/byte
    ('PDF',    7.2000, 0.3000),   -- threshold ≈ 7.50 bits/byte
    ('JPG',    7.7000, 0.1000),   -- threshold ≈ 7.80 bits/byte  ← ultra-sensitive
    ('PNG',    7.5000, 0.1500),   -- threshold ≈ 7.65 bits/byte
    ('DOCX',   7.1000, 0.3500),   -- threshold ≈ 7.45 bits/byte
    ('XLSX',   7.0500, 0.3500),   -- threshold ≈ 7.40 bits/byte
    ('ZIP',    7.9000, 0.0700),   -- threshold ≈ 7.97 bits/byte  ← tightest
    ('MP3',    7.6000, 0.1500),   -- threshold ≈ 7.75 bits/byte
    ('EXE',    6.0000, 1.0000),   -- threshold ≈ 7.00 bits/byte  ← widest
    ('BIN',    5.5000, 1.2000)    -- threshold ≈ 6.70 bits/byte
ON CONFLICT (file_type) DO UPDATE
    SET mean_entropy    = EXCLUDED.mean_entropy,
        threshold_sigma = EXCLUDED.threshold_sigma,
        updated_at      = NOW();


INSERT INTO users (email, username, password_hash, role) VALUES
('admin@lumenaid.local', 'admin', '$2b$12$placeholder_admin_hash', 'admin'),
('analyst@lumenaid.local', 'analyst', '$2b$12$placeholder_analyst_hash', 'analyst')
ON CONFLICT (email) DO NOTHING;


-- 4. Verification queries
-- SELECT * FROM file_type_registry ORDER BY type_code;
-- SELECT
--     b.file_type,
--     b.mean_entropy,
--     b.threshold_sigma,
--     (b.mean_entropy + b.threshold_sigma) AS anomaly_threshold
-- FROM baselines b
-- ORDER BY b.mean_entropy DESC;
-- SELECT * FROM users;
