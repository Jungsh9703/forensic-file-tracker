import type { Env } from "./env";
import type { LogRecord } from "./normalize";
import type { ForensicRecord } from "./forensic";

const MAX_RECORDS_PER_PUSH = 500;

function groupByAction(records: LogRecord[]): Map<string, LogRecord[]> {
  const map = new Map<string, LogRecord[]>();
  for (const r of records) {
    const list = map.get(r.action) ?? [];
    list.push(r);
    map.set(r.action, list);
  }
  return map;
}

function groupByPhase(records: ForensicRecord[]): Map<string, ForensicRecord[]> {
  const map = new Map<string, ForensicRecord[]>();
  for (const r of records) {
    const phase = r.phase ?? "unknown";
    const list = map.get(phase) ?? [];
    list.push(r);
    map.set(phase, list);
  }
  return map;
}

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function buildHeaders(env: Env): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (env.LOKI_USERNAME && env.LOKI_API_KEY) {
    headers.Authorization = `Basic ${btoa(`${env.LOKI_USERNAME}:${env.LOKI_API_KEY}`)}`;
  }
  // Cloudflare Access Service Token, if the VM's Loki push endpoint is
  // fronted by a Cloudflare Tunnel + Access application (recommended: no
  // inbound port needs to be opened on the VM, and auth is Zero-Trust-native
  // rather than a bespoke reverse-proxy Basic Auth).
  if (env.CF_ACCESS_CLIENT_ID && env.CF_ACCESS_CLIENT_SECRET) {
    headers["CF-Access-Client-Id"] = env.CF_ACCESS_CLIENT_ID;
    headers["CF-Access-Client-Secret"] = env.CF_ACCESS_CLIENT_SECRET;
  }
  return headers;
}

/** Shared POST + error handling for both the http and forensic streams. */
async function postStreams(env: Env, streams: unknown[], label: string): Promise<void> {
  const res = await fetch(env.LOKI_URL, {
    method: "POST",
    headers: buildHeaders(env),
    body: JSON.stringify({ streams }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    // Loki rejects individual entries that are too old relative to a
    // stream's already-seen high-water-mark (per-stream ordering isn't
    // negotiable), returning 400 while still accepting whatever entries
    // in the same push WEREN'T too old. This is expected during backlog
    // catch-up -- once real-time data has advanced a stream's high-water
    // mark, older backlogged entries for that same stream can never be
    // accepted, no matter how many times it's retried. Treating this as a
    // hard failure would keep the R2 object stuck as "not completed"
    // forever, endlessly re-consuming the run budget on data that can
    // never succeed. Log and move on instead of throwing.
    if (res.status === 400 && /too far behind/i.test(body)) {
      console.warn(`gateway-log-pipeline: Loki rejected some stale ${label} entries (expected during backlog catch-up): ${body.slice(0, 300)}`);
      return;
    }
    throw new Error(`Loki push failed (${label}): ${res.status} ${body.slice(0, 500)}`);
  }
}

async function pushBatch(env: Env, records: LogRecord[]): Promise<void> {
  const grouped = groupByAction(records);
  const streams = [...grouped.entries()].map(([action, recs]) => ({
    stream: { job: "gateway_http_logs", action },
    values: recs
      .slice()
      .sort((a, b) => a.timestampMs - b.timestampMs)
      .map((r) => [
        String(r.timestampMs * 1_000_000), // Loki wants a nanosecond epoch string
        JSON.stringify({
          request_id: r.requestId,
          status_code: r.statusCode,
          method: r.method,
          policy_id: r.policyId,
          policy_name: r.policyName,
          host: r.host,
          url: r.url,
          identity: r.identity,
          is_isolated: r.isIsolated,
          src_country: r.srcCountry,
          dst_country: r.dstCountry,
          // Loki's `| json` parser silently DROPS fields whose JSON value is
          // an array/object (it only extracts scalar strings/numbers/bools)
          // -- so a native array here would make `download_dlp_profiles`
          // simply not exist as a label, and `!= "[]"` would then compare
          // against a missing label (effectively always true) instead of
          // actually filtering. Pre-stringify so Loki sees a plain string.
          category_ids: JSON.stringify(r.categoryIds),
          category_names: JSON.stringify(r.categoryNames),
          upload_dlp_profiles: JSON.stringify(r.uploadDlpProfiles),
          download_dlp_profiles: JSON.stringify(r.downloadDlpProfiles),
          upload_dlp_profile_entries: JSON.stringify(r.uploadDlpProfileEntries),
          download_dlp_profile_entries: JSON.stringify(r.downloadDlpProfileEntries),
          gen_ai_prompt_request: r.genAiPromptRequest,
          gen_ai_prompt_response: r.genAiPromptResponse,
          gen_ai_conversation: r.genAiConversation,
          dlp_matched_context: r.dlpMatchedContext,
          raw: r.raw,
        }),
      ]),
  }));

  await postStreams(env, streams, "http");
}

async function pushForensicBatch(env: Env, records: ForensicRecord[]): Promise<void> {
  const grouped = groupByPhase(records);
  const streams = [...grouped.entries()].map(([phase, recs]) => ({
    stream: { job: "gateway_forensic_logs", phase },
    values: recs
      .slice()
      .sort((a, b) => a.timestampMs - b.timestampMs)
      .map((r) => [
        String(r.timestampMs * 1_000_000),
        JSON.stringify({
          forensic_copy_id: r.forensicCopyId,
          gateway_request_id: r.gatewayRequestId,
          triggered_rule_id: r.triggeredRuleId,
          triggered_rule_name: r.triggeredRuleName,
          content_type: r.contentType,
          content_encoding: r.contentEncoding,
          body: r.bodyText,
          body_truncated: r.bodyTruncated,
          decode_error: r.decodeError,
          raw: r.raw,
        }),
      ]),
  }));

  await postStreams(env, streams, "forensic");
}

/**
 * Pushes ALL normalized gateway_http records to Loki (not just errors --
 * see normalize.ts). Stream labels are kept to the single low-cardinality
 * `action` field (Loki indexes by label set, so high-cardinality values
 * like url/ray_id/host must NOT become labels) -- everything else, including
 * the full original record, rides in the log line body as JSON for LogQL
 * `| json` filtering/aggregation in Grafana.
 *
 * Sent in chunks of MAX_RECORDS_PER_PUSH: capturing every line (not just
 * errors) means a single cron run's batch can be large enough to exceed
 * Loki's default per-request size limits, so it's split into several
 * sequential POSTs rather than one giant one.
 */
export async function pushToLoki(env: Env, records: LogRecord[]): Promise<void> {
  if (records.length === 0) return;
  if (!env.LOKI_URL) {
    console.warn("gateway-log-pipeline: Loki destination not configured, skipping push");
    return;
  }

  for (const batch of chunk(records, MAX_RECORDS_PER_PUSH)) {
    await pushBatch(env, batch);
  }
}

/**
 * Pushes DLP Forensic Copies records to Loki, under a separate
 * `gateway_forensic_logs` job label so they land in their own streams
 * (see forensic.ts) rather than mixing with gateway_http traffic. Stream
 * label is `phase` (request/response -- low cardinality); everything else,
 * including the decoded body text, rides in the log line body.
 */
export async function pushForensicToLoki(env: Env, records: ForensicRecord[]): Promise<void> {
  if (records.length === 0) return;
  if (!env.LOKI_URL) {
    console.warn("gateway-log-pipeline: Loki destination not configured, skipping forensic push");
    return;
  }

  for (const batch of chunk(records, MAX_RECORDS_PER_PUSH)) {
    await pushForensicBatch(env, batch);
  }
}
