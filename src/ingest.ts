import type { Env } from "./env";
import { loadConfig, type IngestConfig } from "./config";
import { loadCompletedSet, saveCompletedSet, getObjectCursor, putObjectCursor, deleteObjectCursor } from "./cursor";
import { normalizeRecord, type LogRecord } from "./normalize";
import { normalizeForensicRecord, type ForensicRecord } from "./forensic";
import { pushToLoki, pushForensicToLoki } from "./loki";
import { getPolicyNameMap } from "./policy_names";
import { getDlpNameMap } from "./dlp_profile_names";
import { decryptFields } from "./dlp";

async function decompressToText(obj: R2ObjectBody, key: string): Promise<string> {
  const stream = key.endsWith(".gz") ? obj.body.pipeThrough(new DecompressionStream("gzip")) : obj.body;
  return await new Response(stream).text();
}

interface PrefixResult<T> {
  records: T[];
  newlyCompleted: string[];
  touched: number;
  linesRead: number;
}

/**
 * Shared per-object cursor/resume loop for one R2 prefix. Both Logpush jobs
 * (gateway_http under HTTP_LOG_PREFIX, DLP forensic copies under
 * FORENSIC_LOG_PREFIX) land in the same bucket and need identical
 * list/resume/completed-set bookkeeping -- only how a parsed JSON line turns
 * into a record differs, via parseLine.
 */
async function ingestPrefix<T>(
  env: Env,
  cfg: IngestConfig,
  prefix: string,
  completedSet: Set<string>,
  parseLine: (raw: Record<string, unknown>) => Promise<T | null> | T | null,
): Promise<PrefixResult<T>> {
  const listing = await env.RAW_LOGS_BUCKET.list({ prefix, limit: Math.max(cfg.maxObjectsPerRun * 20, 200) });
  const candidateKeys = listing.objects
    .map((o) => o.key)
    .filter((k) => !completedSet.has(k))
    .slice(0, cfg.maxObjectsPerRun);

  const records: T[] = [];
  const newlyCompleted: string[] = [];
  let touched = 0;
  let linesRead = 0;

  for (const key of candidateKeys) {
    const obj = await env.RAW_LOGS_BUCKET.get(key);
    if (!obj) continue;

    const cursor = await getObjectCursor(env, key);
    const text = await decompressToText(obj, key);
    const lines = text.split("\n").filter((l) => l.trim().length > 0);

    let i = cursor?.nextLine ?? 0;
    const startLine = i;
    const budgetEnd = Math.min(lines.length, i + cfg.maxLinesPerObjectRun);

    for (; i < budgetEnd; i++) {
      const line = lines[i];
      if (!line) continue;
      let raw: Record<string, unknown>;
      try {
        raw = JSON.parse(line);
      } catch {
        continue;
      }
      const parsed = await parseLine(raw);
      if (parsed) records.push(parsed);
    }

    const completed = i >= lines.length;
    if (completed) {
      newlyCompleted.push(key);
      await deleteObjectCursor(env, key);
    } else {
      await putObjectCursor(env, key, { nextLine: i, totalLines: lines.length });
    }

    touched++;
    linesRead += i - startLine;
  }

  return { records, newlyCompleted, touched, linesRead };
}

export interface IngestSummary {
  objectsTouched: number;
  linesRead: number;
  recordsShipped: number;
  forensicObjectsTouched: number;
  forensicLinesRead: number;
  forensicRecordsShipped: number;
}

export async function runIngestion(env: Env): Promise<IngestSummary> {
  const cfg = loadConfig(env);

  const [completedSet, policyNames, dlpNames] = await Promise.all([
    loadCompletedSet(env),
    getPolicyNameMap(env),
    getDlpNameMap(env),
  ]);

  const decryptBudget = { remaining: cfg.maxDecryptionsPerRun };

  const http = await ingestPrefix<LogRecord>(env, cfg, cfg.httpPrefix, completedSet, async (raw) => {
    const record = normalizeRecord(raw, policyNames, dlpNames);
    const decrypted = await decryptFields(raw, env, decryptBudget);
    return { ...record, ...decrypted };
  });

  const forensic = await ingestPrefix<ForensicRecord>(env, cfg, cfg.forensicPrefix, completedSet, (raw) =>
    normalizeForensicRecord(raw, dlpNames),
  );

  // Persist "completed" bookkeeping unconditionally, even if a Loki push
  // throws -- otherwise a failed push leaves these objects with no cursor
  // AND not in completedSet, so the next run re-reads them from scratch and
  // resubmits their (now even staler) original timestamps. Given Loki's
  // per-stream ordering means a retry of old data is often no more likely
  // to succeed than the first attempt (time only moves one direction), that
  // non-atomicity was actively harmful. Prefer forward progress -- still
  // surface the error afterward so it isn't silently lost.
  let pushError: unknown;
  try {
    await pushToLoki(env, http.records);
    await pushForensicToLoki(env, forensic.records);
  } catch (err) {
    pushError = err;
  }

  for (const k of [...http.newlyCompleted, ...forensic.newlyCompleted]) completedSet.add(k);
  await saveCompletedSet(env, completedSet, cfg.completedSetCap);

  if (pushError) throw pushError;

  return {
    objectsTouched: http.touched,
    linesRead: http.linesRead,
    recordsShipped: http.records.length,
    forensicObjectsTouched: forensic.touched,
    forensicLinesRead: forensic.linesRead,
    forensicRecordsShipped: forensic.records.length,
  };
}
