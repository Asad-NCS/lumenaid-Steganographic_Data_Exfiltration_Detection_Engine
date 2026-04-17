Project: LumenAid - Steganographic Data Exfiltration Detection Engine
Architecture Style: Hybrid Polyglot (PostgreSQL + MongoDB)

Core Database Rules:

MongoDB is strictly used to store raw binary file chunks and high-volume, unstructured analysis telemetry/logs.

PostgreSQL handles structured metadata, user data, and detection logic.

The Link: In the Postgres segments table, the column raw_chunk_ref is a varchar that stores the MongoDB Document ObjectID. It is NOT a bytea.

The audit_logs table in Postgres uses a jsonb payload strictly for high-value user actions (like policy changes), not scan telemetry.

PostgreSQL Schema Reference:

users (user_id, email, role)

files (file_id, user_id, file_type, status)

segments (segment_id, file_id, segment_index, entropy_score, raw_chunk_ref)

baselines (baseline_id, file_type, mean_entropy, threshold_sigma)

alerts (alert_id, file_id, severity, entropy_score)

scan_jobs / scan_results (For async processing tracking)