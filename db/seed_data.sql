-- this file is used to insert data into the tables

INSERT INTO file_type_registry (type_code, description)
VALUES
    ('TEXT', 'Plain-text files (.txt, .csv, .log)'),
    ('PDF',  'Portable Document Format'),
    ('JPG',  'JPEG image'),
    ('PNG',  'PNG image')
ON CONFLICT (type_code) DO UPDATE
    SET description = EXCLUDED.description;

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

-- Seed realistic chi-square baselines based on empirical measurements.
-- These are conservative estimates — bulk_calibrate.py will overwrite
-- these with real values once calibration samples are scanned.
UPDATE baselines SET mean_chi = 4500, sigma_chi = 3000 WHERE file_type = 'TEXT';
UPDATE baselines SET mean_chi = 1000, sigma_chi = 8000 WHERE file_type = 'JPG';
UPDATE baselines SET mean_chi = 2400, sigma_chi =  800 WHERE file_type = 'PDF';
UPDATE baselines SET mean_chi =  410, sigma_chi = 2400 WHERE file_type = 'PNG';

INSERT INTO users (email, username, password_hash, role) VALUES
('admin@lumenaid.local',   'admin',   '$2b$12$ROBsC1EbGqJrQDFWw4zs0OSGBDFbjxsyXXbe2DGxnytEwYWVSRd1a',   'admin'),
('analyst@lumenaid.local', 'analyst', '$2b$12$3guOaCWWKocrPjeNyGgNeOIrtYPPJEF0CF0i4px5eHrEwxslPOHYO', 'analyst')
ON CONFLICT (email) DO UPDATE
    SET password_hash = EXCLUDED.password_hash,
        role          = EXCLUDED.role;