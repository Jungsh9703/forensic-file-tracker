import type { Env } from "./env";
import { authorize, fileDownload, json } from "./http_util";
import { runIngestion } from "./ingest";
import { ensureSchema } from "./schema";

/**
 * Step 2 read API over D1 (all token-gated, see http_util.authorize):
 *   GET  /api/transfers   file transfers: email, device, time, host, app, filename (+ filters)
 *   GET  /api/summary     dashboard aggregates over the same filters
 *   GET  /api/files/<request_id>/<sha256>   download the stored file
 *   GET  /api/status      is data arriving? row counts + latest ingested objects
 *   POST /api/ingest      run ingestion now instead of waiting for the cron
 */

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

interface TransferRow {
  ts: number;
  time: string;
  email: string | null;
  device_name: string | null;
  host: string | null;
  application_name: string | null;
  file_name: string | null;
  matched_by: string;
  size: number;
  sha256: string;
  truncated: number;
  content_type: string | null;
  request_id: string;
  url: string | null;
  method: string | null;
  action: string | null;
  policy_name: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  http_matched: number;
}

/** Accepts YYYY-MM-DD (start of that UTC day) or any Date.parse-able string. */
function parseBound(v: string | null, endOfDay: boolean): number | null {
  if (!v) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) {
    const start = Date.parse(`${v}T00:00:00Z`);
    return Number.isNaN(start) ? NaN : endOfDay ? start + 86_400_000 : start;
  }
  return Date.parse(v);
}

function likeContains(v: string): string {
  return `%${v.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

const CONTAINS_FILTERS: [param: string, column: string][] = [
  ["email", "email"],
  ["device", "device_name"],
  ["host", "host"],
  ["app", "application_name"],
  ["file", "file_name"],
];

interface Filter {
  whereSql: string;
  args: (string | number)[];
}

/** Shared by /api/transfers and /api/summary. Text filters are
 * case-insensitive "contains"; from/to filter on the forensic copy time
 * (to is exclusive; a bare date includes that whole day). */
function buildFilter(p: URLSearchParams): Filter | Response {
  const where: string[] = [];
  const args: (string | number)[] = [];

  const from = parseBound(p.get("from"), false);
  const to = parseBound(p.get("to"), true);
  if (Number.isNaN(from) || Number.isNaN(to)) return json({ error: "from/to must be YYYY-MM-DD or an ISO timestamp" }, 400);
  if (from !== null) {
    where.push("ts >= ?");
    args.push(from);
  }
  if (to !== null) {
    where.push("ts < ?");
    args.push(to);
  }
  for (const [param, column] of CONTAINS_FILTERS) {
    const v = p.get(param)?.trim();
    if (!v) continue;
    where.push(`${column} LIKE ? ESCAPE '\\'`);
    args.push(likeContains(v));
  }
  return { whereSql: where.length ? `WHERE ${where.join(" AND ")}` : "", args };
}

/** GET /api/transfers?from=&to=&email=&device=&host=&app=&file=&limit=&offset= */
async function handleTransfers(url: URL, env: Env): Promise<Response> {
  const p = url.searchParams;
  const filter = buildFilter(p);
  if (filter instanceof Response) return filter;
  const { whereSql, args } = filter;

  const limit = Math.min(Math.max(Number(p.get("limit") ?? DEFAULT_LIMIT) || DEFAULT_LIMIT, 1), MAX_LIMIT);
  const offset = Math.max(Number(p.get("offset") ?? 0) || 0, 0);

  const [rows, total] = await env.DB.batch<TransferRow | { n: number }>([
    env.DB.prepare(`SELECT * FROM file_transfers ${whereSql} ORDER BY ts DESC LIMIT ? OFFSET ?`).bind(...args, limit, offset),
    env.DB.prepare(`SELECT count(*) AS n FROM file_transfers ${whereSql}`).bind(...args),
  ]);

  const items = (rows!.results as TransferRow[]).map((r) => ({
    time: r.time,
    email: r.email,
    deviceName: r.device_name,
    host: r.host,
    applicationName: r.application_name,
    fileName: r.file_name,
    matchedBy: r.matched_by,
    size: r.size,
    sha256: r.sha256,
    truncated: r.truncated === 1,
    contentType: r.content_type,
    requestId: r.request_id,
    url: r.url,
    method: r.method,
    action: r.action,
    policyName: r.policy_name,
    sourceIP: r.source_ip,
    destinationIP: r.destination_ip,
    httpMatched: r.http_matched === 1,
    downloadPath: `/api/files/${encodeURIComponent(r.request_id)}/${r.sha256}`,
  }));

  return json({ total: (total!.results[0] as { n: number } | undefined)?.n ?? 0, limit, offset, items });
}

const TOP_N = 5;

/** GET /api/summary -- dashboard aggregates over the same filters as
 * /api/transfers: totals, per-UTC-day counts, top hosts and users. */
async function handleSummary(url: URL, env: Env): Promise<Response> {
  const filter = buildFilter(url.searchParams);
  if (filter instanceof Response) return filter;
  const { whereSql, args } = filter;
  const and = whereSql ? `${whereSql} AND` : "WHERE";

  const [totals, byDay, topHosts, topUsers] = await env.DB.batch([
    env.DB.prepare(
      `SELECT count(*) AS transfers, count(DISTINCT email) AS users, count(DISTINCT device_name) AS devices,
              COALESCE(sum(size), 0) AS bytes, COALESCE(sum(http_matched = 0), 0) AS waiting_for_http
       FROM file_transfers ${whereSql}`,
    ).bind(...args),
    env.DB.prepare(
      `SELECT strftime('%Y-%m-%d', ts / 1000, 'unixepoch') AS day, count(*) AS n
       FROM file_transfers ${whereSql} GROUP BY day ORDER BY day`,
    ).bind(...args),
    env.DB.prepare(
      `SELECT host AS label, count(*) AS n FROM file_transfers ${and} host IS NOT NULL
       GROUP BY host ORDER BY n DESC, host LIMIT ${TOP_N}`,
    ).bind(...args),
    env.DB.prepare(
      `SELECT email AS label, count(*) AS n FROM file_transfers ${and} email IS NOT NULL
       GROUP BY email ORDER BY n DESC, email LIMIT ${TOP_N}`,
    ).bind(...args),
  ]);

  const t = totals!.results[0] as Record<string, number>;
  return json({
    transfers: t.transfers ?? 0,
    users: t.users ?? 0,
    devices: t.devices ?? 0,
    bytes: t.bytes ?? 0,
    waitingForHttp: t.waiting_for_http ?? 0,
    byDay: byDay!.results,
    topHosts: topHosts!.results,
    topUsers: topUsers!.results,
  });
}

/** GET /api/files/<request_id>/<sha256> */
async function handleFile(path: string, env: Env): Promise<Response> {
  const m = /^\/api\/files\/([^/]+)\/([0-9a-f]{64})$/.exec(path);
  if (!m) return json({ error: "expected /api/files/<request_id>/<sha256>" }, 400);
  const requestId = decodeURIComponent(m[1]!);
  const sha256 = m[2]!;

  const row = await env.DB.prepare(`SELECT file_name, r2_key, truncated FROM file_transfers WHERE request_id = ? AND sha256 = ? LIMIT 1`)
    .bind(requestId, sha256)
    .first<{ file_name: string | null; r2_key: string; truncated: number }>();
  if (!row) return json({ error: "file not found" }, 404);

  const obj = await env.LOGS_BUCKET.get(row.r2_key);
  if (!obj) return json({ error: "file row exists but its R2 object is missing", r2Key: row.r2_key }, 404);
  return fileDownload(obj.body, row.file_name ?? `${sha256}.bin`, {
    "x-file-sha256": sha256,
    "x-file-truncated": String(row.truncated === 1),
  });
}

/** GET /api/status -- answers "is data actually arriving?" in one call. */
async function handleStatus(env: Env): Promise<Response> {
  const [counts, latest, unmatched] = await env.DB.batch([
    env.DB.prepare(
      `SELECT
         (SELECT count(*) FROM http_requests) AS http_requests,
         (SELECT count(*) FROM forensic_files) AS forensic_files,
         (SELECT max(ts) FROM http_requests) AS last_http_ts,
         (SELECT max(ts) FROM forensic_files) AS last_file_ts,
         (SELECT count(*) FROM ingested_objects) AS ingested_objects,
         (SELECT max(ingested_at) FROM ingested_objects) AS last_ingested_at`,
    ),
    env.DB.prepare(`SELECT key, prefix, lines, rows, ingested_at FROM ingested_objects ORDER BY ingested_at DESC LIMIT 10`),
    env.DB.prepare(`SELECT count(*) AS n FROM file_transfers WHERE http_matched = 0`),
  ]);

  const c = counts!.results[0] as Record<string, number | null>;
  const iso = (ms: number | null | undefined) => (ms ? new Date(ms).toISOString() : null);
  return json({
    rows: { httpRequests: c.http_requests, forensicFiles: c.forensic_files, ingestedObjects: c.ingested_objects },
    lastSeen: { httpRequest: iso(c.last_http_ts), forensicFile: iso(c.last_file_ts), ingestRun: iso(c.last_ingested_at) },
    // Files whose gateway_http row hasn't arrived (or was never stored) --
    // email/device/host/app show as null for these until it does.
    filesWithoutHttpMatch: (unmatched!.results[0] as { n: number } | undefined)?.n ?? 0,
    recentObjects: (latest!.results as { key: string; prefix: string; lines: number; rows: number; ingested_at: number }[]).map((o) => ({
      key: o.key,
      prefix: o.prefix,
      lines: o.lines,
      rows: o.rows,
      ingestedAt: iso(o.ingested_at),
    })),
  });
}

/** Routes /api/* -- returns null for any other path. */
export async function handleApiRoutes(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/")) return null;

  const denied = authorize(request, env);
  if (denied) return denied;
  await ensureSchema(env.DB);

  if (url.pathname === "/api/ingest") {
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
    return json(await runIngestion(env));
  }
  if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
  if (url.pathname === "/api/transfers") return handleTransfers(url, env);
  if (url.pathname === "/api/summary") return handleSummary(url, env);
  if (url.pathname === "/api/status") return handleStatus(env);
  if (url.pathname.startsWith("/api/files/")) return handleFile(url.pathname, env);
  return json({ error: "Not found" }, 404);
}
