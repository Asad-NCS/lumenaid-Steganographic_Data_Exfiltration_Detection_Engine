-- this file is used to insert data into the tables
-- NOTE: Scope strictly reduced to TEXT, JPG, and PDF for flawless demo calibration.

INSERT INTO file_type_registry (type_code, description)
VALUES
    ('TEXT', 'Plain-text files (.txt, .csv, .log)'),
    ('PDF',  'Portable Document Format'),
    ('JPG',  'JPEG image'),
    ('PNG',  'PNG image')
ON CONFLICT (type_code) DO UPDATE
    SET description = EXCLUDED.description;

-- PRECISION CALIBRATION
-- TEXT is very low entropy. Any hidden data spikes it massively.
-- JPG and PNG are naturally high but consistent.
-- PDF is variable due to FlateDecode but usually stays below 7.8
INSERT INTO baselines (file_type, mean_entropy, threshold_sigma)
VALUES
    ('TEXT',   4.5000, 0.4000),
    ('PDF',    7.7000, 0.2000),
    ('JPG',    7.7500, 0.1500),
    ('PNG',    7.5000, 0.1500)
ON CONFLICT (file_type) DO UPDATE
    SET mean_entropy    = EXCLUDED.mean_entropy,
        threshold_sigma = EXCLUDED.threshold_sigma,
        updated_at      = NOW();

INSERT INTO users (email, username, password_hash, role) VALUES
('admin@lumenaid.local',   'admin',   '$2b$12$ROBsC1EbGqJrQDFWw4zs0OSGBDFbjxsyXXbe2DGxnytEwYWVSRd1a',   'admin'),
('analyst@lumenaid.local', 'analyst', '$2b$12$3guOaCWWKocrPjeNyGgNeOIrtYPPJEF0CF0i4px5eHrEwxslPOHYO', 'analyst')
ON CONFLICT (email) DO UPDATE
    SET password_hash = EXCLUDED.password_hash,
        role          = EXCLUDED.role;