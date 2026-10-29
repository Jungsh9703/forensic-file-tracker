import type { Env } from "./env";
import { decodeForensicCopy, parseFileInfo, resolveFiles, sha256Hex, type DecodedCopy, type FileInfoEntry } from "./forensic_files";
import { parseTimeMs } from "./decode";

/**
 * Step 1 of forensic file tracking (see docs/forensic-file-tracking.md):
 * given one Gateway request ID, find its DLP forensic copies and its
 * gateway_http record directly in R2, decode the uploaded file(s) and settle
 * each filename by hash against FileInfo. No database yet -- this scans R2
 * objects by date, so it's for looking up a single request, not bulk
 * queries (that's step 2, D1).
 */

const DEFAULT_MAX_LOOKUP_OBJECTS = 200;
const BODY_PREVIEW_CHARS = 2000;

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

/** These endpoints return real uploaded file contents, so unlike /run they
 * refuse to run at all without LOOKUP_TOKEN configured. Bearer header, not
 * a query param, so the token doesn't end up in access logs. */
async function authorized(request: Request, env: Env): Promise<Response | null> {
  if (!env.LOOKUP_TOKEN) return json({ error: "LOOKUP_TOKEN is not configured" }, 503);
  const given = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  const a = new TextEncoder().encode(given);
  const b = new TextEncoder().encode(env.LOOKUP_TOKEN);
  if (a.byteLength !== b.byteLength || !crypto.subtle.timingSafeEqual(a, b)) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null;
}

/** YYYYMMDD strings to scan: the given UTC day and the next one (requests
 * near midnight can land in the following day's batch), or today and
 * yesterday when no date is given. */
function scanDates(date: string | null): string[] | null {
  let base: Date;
  if (date) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    base = new Date(`${date}T00:00:00Z`);
    if (Number.isNaN(base.getTime())) return null;
  } else {
    base = new Date(Date.now() - 86_400_000);
  }
  const fmt = (d: Date) => d.toISOString().slice(0, 10).replace(/-/g, "");
  return [fmt(base), fmt(new Date(base.getTime() + 86_400_000))];
}

interface ScanBudget {
  remaining: number;
  scanned: number;
}

/** Logpush writes under "<prefix><YYYYMMDD>/..." when the destination path
 * uses {DATE}; if no such folders exist (e.g. local seed data, or a job set
 * up without {DATE}), fall back to every key under the prefix. */
async function listKeys(env: Env, prefix: string, dates: string[], budget: ScanBudget): Promise<string[]> {
  const listAll = async (p: string) => {
    const keys: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await env.LOGS_BUCKET.list({ prefix: p, cursor, limit: 1000 });
      keys.push(...page.objects.map((o) => o.key));
      cursor = page.truncated ? page.cursor : undefined;
    } while (cursor && keys.length < budget.remaining);
    return keys;
  };

  let keys: string[] = [];
  for (const d of dates) keys.push(...(await listAll(`${prefix}${d}/`)));
  if (keys.length === 0) keys = await listAll(prefix);
  return keys;
}

/** Streams through objects under prefix and returns every parsed line for
 * which match() is true. Cheap substring check first so we only JSON.parse
 * lines that mention the ID at all. */
async function scanPrefix(
  env: Env,
  prefix: string,
  dates: string[],
  needle: string,
  match: (raw: Record<string, unknown>) => boolean,
  budget: ScanBudget,
  stopAtFirst: boolean,
): Promise<Record<string, unknown>[]> {
  const found: Record<string, unknown>[] = [];
  for (const key of await listKeys(env, prefix, dates, budget)) {
    if (budget.remaining <= 0) break;
    const obj = await env.LOGS_BUCKET.get(key);
    if (!obj) continue;
    budget.remaining--;
    budget.scanned++;
    const stream = key.endsWith(".gz") ? obj.body.pipeThrough(new DecompressionStream("gzip")) : obj.body;
    const text = await new Response(stream).text();
    for (const line of text.split("\n")) {
      if (!line.includes(needle)) continue;
      try {
        const raw = JSON.parse(line) as Record<string, unknown>;
        if (match(raw)) found.push(raw);
      } catch {
        continue;
      }
    }
    if (stopAtFirst && found.length > 0) break;
  }
  return found;
}

interface HttpSummary {
  datetime: string;
  requestId: string | null;
  email: string | null;
  userId: string | null;
  sourceIP: string | null;
  sourceInternalIP: string | null;
  destinationIP: string | null;
  host: string | null;
  url: string | null;
  method: string | null;
  action: string | null;
  policyName: string | null;
  uploadedFileNames: string[];
  fileInfo: FileInfoEntry[];
}

function summarizeHttp(raw: Record<string, unknown>): HttpSummary {
  return {
    datetime: new Date(parseTimeMs(raw.Datetime)).toISOString(),
    requestId: str(raw.RequestID),
    email: str(raw.Email),
    userId: str(raw.UserID),
    sourceIP: str(raw.SourceIP),
    sourceInternalIP: str(raw.SourceInternalIP),
    destinationIP: str(raw.DestinationIP),
    host: str(raw.HTTPHost),
    url: str(raw.URL),
    method: str(raw.HTTPMethod),
    action: str(raw.Action),
    policyName: str(raw.PolicyName),
    uploadedFileNames: strArray(raw.UploadedFileNames),
    fileInfo: parseFileInfo(raw.FileInfo),
  };
}

interface Found {
  copies: DecodedCopy[];
  http: HttpSummary | null;
  scanned: { forensicObjects: number; httpObjects: number; capped: boolean };
}

async function findRequest(env: Env, requestId: string, dates: string[], withHttp: boolean): Promise<Found> {
  const forensicPrefix = env.FORENSIC_LOG_PREFIX ?? "forensic/";
  const httpPrefix = env.HTTP_LOG_PREFIX ?? "http/";
  const max = Number(env.MAX_LOOKUP_OBJECTS ?? DEFAULT_MAX_LOOKUP_OBJECTS);

  const fBudget: ScanBudget = { remaining: max, scanned: 0 };
  const rawCopies = await scanPrefix(env, forensicPrefix, dates, requestId, (r) => r.GatewayRequestID === requestId, fBudget, false);
  const copies = rawCopies.map(decodeForensicCopy).sort((a, b) => a.timestampMs - b.timestampMs);

  let http: HttpSummary | null = null;
  const hBudget: ScanBudget = { remaining: max, scanned: 0 };
  if (withHttp) {
    const rawHttp = await scanPrefix(env, httpPrefix, dates, requestId, (r) => r.RequestID === requestId, hBudget, true);
    http = rawHttp[0] ? summarizeHttp(rawHttp[0]) : null;
  }

  return {
    copies,
    http,
    scanned: {
      forensicObjects: fBudget.scanned,
      httpObjects: hBudget.scanned,
      capped: fBudget.remaining <= 0 || hBudget.remaining <= 0,
    },
  };
}

function bodyPreview(body: Uint8Array | null): string | null {
  if (!body) return null;
  const text = new TextDecoder("utf-8").decode(body.subarray(0, BODY_PREVIEW_CHARS * 4));
  return text.length > BODY_PREVIEW_CHARS ? text.slice(0, BODY_PREVIEW_CHARS) + "…" : text;
}

/** GET /forensic/lookup?request_id=<GatewayRequestID>[&date=YYYY-MM-DD] */
async function handleLookup(url: URL, env: Env): Promise<Response> {
  const requestId = url.searchParams.get("request_id")?.trim();
  if (!requestId) return json({ error: "request_id is required" }, 400);
  const dates = scanDates(url.searchParams.get("date"));
  if (!dates) return json({ error: "date must be YYYY-MM-DD" }, 400);

  const { copies, http, scanned } = await findRequest(env, requestId, dates, true);

  const outCopies = [];
  for (const c of copies) {
    const files = await resolveFiles(c.files, http?.fileInfo ?? [], http?.uploadedFileNames ?? []);
    outCopies.push({
      forensicCopyId: c.forensicCopyId,
      datetime: c.datetime,
      gatewayRequestId: c.gatewayRequestId,
      phase: c.phase,
      triggeredRuleId: c.triggeredRuleId,
      headers: c.headers,
      decodeError: c.decodeError,
      payloadBytes: c.body?.length ?? 0,
      // Only for non-file bodies (prompts, JSON) -- file bytes are fetched via downloadPath.
      bodyPreview: c.files.length === 0 ? bodyPreview(c.body) : null,
      files: files.map((f) => ({
        ...f,
        downloadPath: `/forensic/file?request_id=${encodeURIComponent(requestId)}&sha256=${f.sha256}&date=${c.datetime.slice(0, 10)}`,
      })),
    });
  }

  return json({
    requestId,
    scannedDates: dates,
    scanned,
    http,
    copies: outCopies,
  });
}

/** RFC 6266 filename + filename* so non-ASCII (e.g. Korean) names survive. */
function attachmentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/** GET /forensic/file?request_id=<id>&sha256=<hex>[&date=YYYY-MM-DD]
 * Re-extracts the file from the forensic copy and returns its bytes. Always
 * served as an octet-stream download, never inline -- the content is
 * arbitrary user-uploaded data (could be HTML/JS). */
async function handleFile(url: URL, env: Env): Promise<Response> {
  const requestId = url.searchParams.get("request_id")?.trim();
  const wanted = url.searchParams.get("sha256")?.trim().toLowerCase();
  if (!requestId || !wanted || !/^[0-9a-f]{64}$/.test(wanted)) {
    return json({ error: "request_id and a 64-char hex sha256 are required" }, 400);
  }
  const dates = scanDates(url.searchParams.get("date"));
  if (!dates) return json({ error: "date must be YYYY-MM-DD" }, 400);

  const { copies, http } = await findRequest(env, requestId, dates, true);
  for (const c of copies) {
    for (const f of c.files) {
      if ((await sha256Hex(f.bytes)) !== wanted) continue;
      const [resolved] = await resolveFiles([f], http?.fileInfo ?? [], []);
      const name = resolved?.fileName ?? `${wanted}.bin`;
      return new Response(f.bytes, {
        headers: {
          "content-type": "application/octet-stream",
          "content-disposition": attachmentDisposition(name),
          "x-content-type-options": "nosniff",
          "cache-control": "no-store",
          "x-file-sha256": wanted,
          "x-file-truncated": String(f.truncated),
        },
      });
    }
  }
  return json({ error: "file not found for that request_id/sha256" }, 404);
}

/** Routes /forensic/* -- returns null for any other path. */
export async function handleForensicRoutes(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/forensic/")) return null;
  if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);

  const denied = await authorized(request, env);
  if (denied) return denied;

  if (url.pathname === "/forensic/lookup") return handleLookup(url, env);
  if (url.pathname === "/forensic/file") return handleFile(url, env);
  return json({ error: "Not found" }, 404);
}
