-- this file is used to insert data into the tables

INSERT INTO file_type_registry (type_code, description)
VALUES
    ('TEXT', 'Plain-text files (.txt, .csv, .log)'),
    ('PDF',  'Portable Document Format'),
    ('JPG',  'JPEG image'),
    ('PNG',  'PNG image'),
    ('DOCX', 'Microsoft Word Open XML'),
    ('XLSX', 'Microsoft Excel Open XML'),
    ('ZIP',  'Generic ZIP archive'),
    ('MP3',  'MP3 audio'),
    ('EXE',  'Windows PE executable'),
    ('BIN',  'Generic binary blob')
ON CONFLICT (type_code) DO UPDATE
    SET description = EXCLUDED.description;

INSERT INTO baselines (file_type, mean_entropy, threshold_sigma)
VALUES
    ('TEXT',   4.4000, 0.5000),
    ('PDF',    7.2000, 0.3000),
    ('JPG',    7.7000, 0.1000),
    ('PNG',    7.5000, 0.1500),
    ('DOCX',   7.1000, 0.3500),
    ('XLSX',   7.0500, 0.3500),
    ('ZIP',    7.9000, 0.0700),
    ('MP3',    7.6000, 0.1500),
    ('EXE',    6.0000, 1.0000),
    ('BIN',    5.5000, 1.2000)
ON CONFLICT (file_type) DO UPDATE
    SET mean_entropy    = EXCLUDED.mean_entropy,
        threshold_sigma = EXCLUDED.threshold_sigma,
        updated_at      = NOW();

INSERT INTO users (email, username, password_hash, role) VALUES
('admin@lumenaid.local',   'admin',   '$2b$12$placeholder_admin_hash',   'admin'),
('analyst@lumenaid.local', 'analyst', '$2b$12$placeholder_analyst_hash', 'analyst')
ON CONFLICT (email) DO NOTHING;