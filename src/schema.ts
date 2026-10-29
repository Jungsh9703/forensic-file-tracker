/**
 * D1 schema (step 2). Applied by the Worker itself on first use instead of
 * `wrangler d1 migrations`, so a fresh Deploy-to-Cloudflare / auto-
 * provisioned database works without a separate migration step. Every
 * statement is idempotent.
 *
 * The two Logpush datasets arrive independently (either can land first),
 * so they're stored as-is in two tables and joined only at read time by
 * the file_transfers view -- a late-arriving gateway_http row fills in
 * email/device/host/app/filename for already-stored files automatically.
 */
const STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS http_requests (
    request_id          TEXT PRIMARY KEY,
    ts                  INTEGER NOT NULL,   -- epoch ms
    email               TEXT,
    user_id             TEXT,
    device_name         TEXT,
    device_id           TEXT,
    host                TEXT,
    url                 TEXT,
    method              TEXT,
    action              TEXT,
    policy_name         TEXT,
    application_names   TEXT,               -- JSON array of strings
    source_ip           TEXT,
    destination_ip      TEXT,
    uploaded_file_names TEXT,               -- JSON array of strings
    file_info           TEXT                -- JSON array of {fileName, fileHash, fileSize, contentType, direction, action}
  )`,
  `CREATE INDEX IF NOT EXISTS idx_http_ts ON http_requests (ts)`,
  `CREATE INDEX IF NOT EXISTS idx_http_email ON http_requests (email)`,

  `CREATE TABLE IF NOT EXISTS forensic_files (
    forensic_copy_id TEXT NOT NULL,
    file_index       INTEGER NOT NULL,      -- position within the copy (multipart part order)
    request_id       TEXT NOT NULL,         -- GatewayRequestID
    ts               INTEGER NOT NULL,      -- epoch ms, forensic copy Datetime
    part_file_name   TEXT,                  -- multipart filename=, often just "blob"
    content_type     TEXT,
    size             INTEGER NOT NULL,
    sha256           TEXT NOT NULL,
    sha1             TEXT NOT NULL,
    md5              TEXT NOT NULL,
    truncated        INTEGER NOT NULL DEFAULT 0,
    r2_key           TEXT NOT NULL,         -- extracted file bytes in R2
    PRIMARY KEY (forensic_copy_id, file_index)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_files_request ON forensic_files (request_id)`,
  `CREATE INDEX IF NOT EXISTS idx_files_ts ON forensic_files (ts)`,
  `CREATE INDEX IF NOT EXISTS idx_files_sha256 ON forensic_files (sha256)`,

  `CREATE TABLE IF NOT EXISTS ingested_objects (
    key         TEXT PRIMARY KEY,           -- R2 object key
    prefix      TEXT NOT NULL,
    lines       INTEGER NOT NULL,
    rows        INTEGER NOT NULL,
    ingested_at INTEGER NOT NULL            -- epoch ms
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ingested_at ON ingested_objects (ingested_at)`,

  // Filename precedence matches resolveFiles() in forensic_files.ts: the
  // FileInfo entry whose file_hash equals one of the file's own digests
  // (algorithm unknown, so all three are compared), then the multipart
  // filename, then UploadedFileNames by position.
  `CREATE VIEW IF NOT EXISTS file_transfers AS
  SELECT
    f.ts,
    strftime('%Y-%m-%dT%H:%M:%fZ', f.ts / 1000.0, 'unixepoch') AS time,
    h.email,
    h.device_name,
    h.host,
    (SELECT group_concat(a.value, ', ') FROM json_each(COALESCE(h.application_names, '[]')) a) AS application_name,
    COALESCE(
      (SELECT json_extract(j.value, '$.fileName') FROM json_each(COALESCE(h.file_info, '[]')) j
        WHERE lower(json_extract(j.value, '$.fileHash')) IN (f.sha256, f.sha1, f.md5) LIMIT 1),
      f.part_file_name,
      json_extract(h.uploaded_file_names, '$[' || f.file_index || ']')
    ) AS file_name,
    CASE
      WHEN EXISTS (SELECT 1 FROM json_each(COALESCE(h.file_info, '[]')) j
        WHERE lower(json_extract(j.value, '$.fileHash')) IN (f.sha256, f.sha1, f.md5)) THEN 'hash'
      WHEN f.part_file_name IS NOT NULL THEN 'multipart'
      WHEN json_extract(h.uploaded_file_names, '$[' || f.file_index || ']') IS NOT NULL THEN 'uploaded_file_names'
      ELSE 'none'
    END AS matched_by,
    f.size,
    f.sha256,
    f.truncated,
    f.content_type,
    f.request_id,
    f.forensic_copy_id,
    f.r2_key,
    h.url,
    h.method,
    h.action,
    h.policy_name,
    h.source_ip,
    h.destination_ip,
    h.request_id IS NOT NULL AS http_matched
  FROM forensic_files f
  LEFT JOIN http_requests h ON h.request_id = f.request_id`,
];

let schemaReady = false;

/** Runs once per isolate; cheap no-ops after the first deploy. */
export async function ensureSchema(db: D1Database): Promise<void> {
  if (schemaReady) return;
  await db.batch(STATEMENTS.map((s) => db.prepare(s)));
  schemaReady = true;
}
