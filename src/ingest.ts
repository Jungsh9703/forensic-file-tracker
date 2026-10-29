import type { Env } from "./env";
import { parseTimeMs } from "./decode";
import { decodeForensicCopy, digestHex, parseFileInfo } from "./forensic_files";
import { ensureSchema } from "./schema";

/**
 * Step 2: drains new Logpush objects from R2 into D1 (see schema.ts).
 * Each R2 object is processed whole and recorded in ingested_objects only
 * after all its rows are written; every write is an upsert, so an object
 * that fails midway is simply redone on the next run.
 */

const DEFAULTS = { maxObjectsPerRun: 20, lookbackDays: 3, filesPrefix: "files/" };
const BATCH_SIZE = 50;
/** D1 caps bound parameters per statement at 100. */
const IN_CHUNK = 90;
const MAX_LIST_PAGES = 10;

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function utcDates(lookbackDays: number): string[] {
  const out: string[] = [];
  for (let i = lookbackDays - 1; i >= 0; i--) {
    out.push(new Date(Date.now() - i * 86_400_000).toISOString().slice(0, 10).replace(/-/g, ""));
  }
  return out;
}

async function listAll(env: Env, prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_LIST_PAGES; page++) {
    const res = await env.LOGS_BUCKET.list({ prefix, cursor, limit: 1000 });
    keys.push(...res.objects.map((o) => o.key));
    if (!res.truncated) break;
    cursor = res.cursor;
  }
  return keys;
}

/**
 * New (not yet ingested) object keys under prefix, oldest first. Logpush
 * writes "<prefix><YYYYMMDD>/..." when its destination path uses {DATE};
 * then only the last lookbackDays folders are listed. Without date folders
 * (a job set up without {DATE}, or local seed data) the whole prefix is.
 */
async function newKeys(env: Env, prefix: string, lookbackDays: number, limit: number): Promise<string[]> {
  const top = await env.LOGS_BUCKET.list({ prefix, delimiter: "/" });
  const dated = top.delimitedPrefixes.some((p) => /^\d{8}\/$/.test(p.slice(prefix.length)));

  let keys: string[] = [];
  if (dated) {
    for (const d of utcDates(lookbackDays)) keys.push(...(await listAll(env, `${prefix}${d}/`)));
  } else {
    keys = await listAll(env, prefix);
  }
  keys.sort();

  const done = new Set<string>();
  for (let i = 0; i < keys.length; i += IN_CHUNK) {
    const chunk = keys.slice(i, i + IN_CHUNK);
    const res = await env.DB.prepare(`SELECT key FROM ingested_objects WHERE key IN (${chunk.map(() => "?").join(",")})`)
      .bind(...chunk)
      .all<{ key: string }>();
    for (const r of res.results) done.add(r.key);
  }
  return keys.filter((k) => !done.has(k)).slice(0, limit);
}

async function readLines(env: Env, key: string): Promise<string[] | null> {
  const obj = await env.LOGS_BUCKET.get(key);
  if (!obj) return null;
  const stream = key.endsWith(".gz") ? obj.body.pipeThrough(new DecompressionStream("gzip")) : obj.body;
  const text = await new Response(stream).text();
  return text.split("\n").filter((l) => l.trim().length > 0);
}

async function runBatches(db: D1Database, stmts: D1PreparedStatement[]): Promise<void> {
  for (let i = 0; i < stmts.length; i += BATCH_SIZE) await db.batch(stmts.slice(i, i + BATCH_SIZE));
}

/** Cheap pre-JSON.parse check (Logpush writes compact JSON): only lines that
 * could carry a file upload are kept -- forensic copies of file uploads
 * always sit on a POST/PUT/PATCH, so the rest of gateway_http (the bulk of
 * the volume) is never parsed or stored. */
const HTTP_HINTS = ['"HTTPMethod":"POST"', '"HTTPMethod":"PUT"', '"HTTPMethod":"PATCH"', '"UploadedFileNames":["', '"file_hash"'];
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);

function httpStatement(db: D1Database, raw: Record<string, unknown>): D1PreparedStatement | null {
  const requestId = str(raw.RequestID);
  if (!requestId) return null;
  const method = str(raw.HTTPMethod);
  const fileInfo = parseFileInfo(raw.FileInfo);
  const uploaded = strArray(raw.UploadedFileNames);
  if (!(method && WRITE_METHODS.has(method.toUpperCase())) && fileInfo.length === 0 && uploaded.length === 0) return null;

  return db
    .prepare(
      `INSERT OR REPLACE INTO http_requests
        (request_id, ts, email, user_id, device_name, device_id, host, url, method, action, policy_name,
         application_names, source_ip, destination_ip, uploaded_file_names, file_info)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      requestId,
      parseTimeMs(raw.Datetime),
      str(raw.Email),
      str(raw.UserID),
      str(raw.DeviceName),
      str(raw.DeviceID),
      str(raw.HTTPHost),
      str(raw.URL),
      method,
      str(raw.Action),
      str(raw.PolicyName),
      JSON.stringify(strArray(raw.ApplicationNames)),
      str(raw.SourceIP),
      str(raw.DestinationIP),
      JSON.stringify(uploaded),
      JSON.stringify(fileInfo),
    );
}

async function ingestHttpObject(env: Env, lines: string[]): Promise<number> {
  const stmts: D1PreparedStatement[] = [];
  for (const line of lines) {
    if (!HTTP_HINTS.some((h) => line.includes(h))) continue;
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(line);
    } catch {
      continue;
    }
    const stmt = httpStatement(env.DB, raw);
    if (stmt) stmts.push(stmt);
  }
  await runBatches(env.DB, stmts);
  return stmts.length;
}

/** Stores each extracted file's bytes in R2 under FILES_PREFIX (so later
 * downloads don't need to re-decode the Logpush object) and one row per
 * file in D1. Forensic copies with no file in them (prompts, API bodies,
 * response phases) produce no rows. */
async function ingestForensicObject(env: Env, lines: string[], filesPrefix: string): Promise<number> {
  const stmts: D1PreparedStatement[] = [];
  for (const line of lines) {
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(line);
    } catch {
      continue;
    }
    const copy = decodeForensicCopy(raw);
    if (!copy.gatewayRequestId || copy.files.length === 0) continue;
    const copyId = copy.forensicCopyId ?? `${copy.gatewayRequestId}:${copy.timestampMs}`;

    for (const [idx, f] of copy.files.entries()) {
      const [sha256, sha1, md5] = await Promise.all([
        digestHex("SHA-256", f.bytes),
        digestHex("SHA-1", f.bytes),
        digestHex("MD5", f.bytes),
      ]);
      const r2Key = `${filesPrefix}${copy.gatewayRequestId}/${sha256}`;
      await env.LOGS_BUCKET.put(r2Key, f.bytes, {
        httpMetadata: { contentType: "application/octet-stream" },
        customMetadata: { forensicCopyId: copyId, partFileName: f.partFileName ?? "" },
      });
      stmts.push(
        env.DB.prepare(
          `INSERT OR REPLACE INTO forensic_files
            (forensic_copy_id, file_index, request_id, ts, part_file_name, content_type, size, sha256, sha1, md5, truncated, r2_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(copyId, idx, copy.gatewayRequestId, copy.timestampMs, f.partFileName, f.contentType, f.bytes.length, sha256, sha1, md5, f.truncated ? 1 : 0, r2Key),
      );
    }
  }
  await runBatches(env.DB, stmts);
  return stmts.length;
}

interface PrefixSummary {
  objects: number;
  lines: number;
  rows: number;
  errors: { key: string; error: string }[];
}

async function ingestPrefix(
  env: Env,
  prefix: string,
  cfg: typeof DEFAULTS,
  handle: (lines: string[]) => Promise<number>,
): Promise<PrefixSummary> {
  const summary: PrefixSummary = { objects: 0, lines: 0, rows: 0, errors: [] };
  for (const key of await newKeys(env, prefix, cfg.lookbackDays, cfg.maxObjectsPerRun)) {
    try {
      const lines = await readLines(env, key);
      if (!lines) continue;
      const rows = await handle(lines);
      await env.DB.prepare(`INSERT OR REPLACE INTO ingested_objects (key, prefix, lines, rows, ingested_at) VALUES (?, ?, ?, ?, ?)`)
        .bind(key, prefix, lines.length, rows, Date.now())
        .run();
      summary.objects++;
      summary.lines += lines.length;
      summary.rows += rows;
    } catch (err) {
      // Left out of ingested_objects, so the next run retries it.
      summary.errors.push({ key, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return summary;
}

export interface IngestSummary {
  http: PrefixSummary;
  forensic: PrefixSummary;
}

export async function runIngestion(env: Env): Promise<IngestSummary> {
  await ensureSchema(env.DB);
  const cfg = {
    maxObjectsPerRun: Number(env.MAX_OBJECTS_PER_RUN ?? DEFAULTS.maxObjectsPerRun),
    lookbackDays: Number(env.LOOKBACK_DAYS ?? DEFAULTS.lookbackDays),
    filesPrefix: env.FILES_PREFIX ?? DEFAULTS.filesPrefix,
  };
  const httpPrefix = env.HTTP_LOG_PREFIX ?? "http/";
  const forensicPrefix = env.FORENSIC_LOG_PREFIX ?? "forensic/";

  const http = await ingestPrefix(env, httpPrefix, cfg, (lines) => ingestHttpObject(env, lines));
  const forensic = await ingestPrefix(env, forensicPrefix, cfg, (lines) => ingestForensicObject(env, lines, cfg.filesPrefix));
  return { http, forensic };
}
