import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import { parseTimeMs } from "./normalize";

export interface ForensicRecord {
  timestampMs: number;
  forensicCopyId: string | null;
  gatewayRequestId: string | null;
  phase: string | null;
  triggeredRuleId: string | null;
  triggeredRuleName: string | null;
  contentType: string | null;
  contentEncoding: string | null;
  /** Decoded (and decompressed, if Content-Encoding says so) body text.
   * null if Payload was missing or couldn't be decoded -- see decodeError. */
  bodyText: string | null;
  bodyTruncated: boolean;
  decodeError: string | null;
  /** Original record minus Payload -- Payload is fully represented by
   * bodyText once decoded, so keeping both would store the same content
   * (plus base64 overhead) twice. */
  raw: Record<string, unknown>;
}

const MAX_BODY_CHARS = 20_000;

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Forensic copy Headers keys have been observed lowercase, but Cloudflare
 * doesn't document a guarantee -- match case-insensitively. */
export function headerValue(headers: unknown, name: string): string | null {
  if (!headers || typeof headers !== "object") return null;
  const rec = headers as Record<string, unknown>;
  const key = Object.keys(rec).find((k) => k.toLowerCase() === name);
  const v = key ? rec[key] : undefined;
  return typeof v === "string" ? v : null;
}

export function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * DLP Forensic Copies are NOT encrypted by Cloudflare (unlike the separate
 * "Payload logging"/"AI prompt logging" HPKE scheme in crypto.ts/dlp.ts) --
 * Payload is just base64, and for streamed/compressed responses (e.g. SSE
 * with Content-Encoding: br) the bytes underneath are plain
 * gzip/deflate/brotli, decodable with no key at all. Confirmed against real
 * sample records: a "request"-phase Payload's base64 decodes directly to
 * readable JSON; a "response"-phase Payload's apparent randomness was
 * explained entirely by its own Headers.content-encoding: br.
 */
export function decompress(bytes: Uint8Array, encoding: string | null): Uint8Array {
  switch ((encoding ?? "").toLowerCase()) {
    case "br":
      return new Uint8Array(brotliDecompressSync(bytes));
    case "gzip":
      return new Uint8Array(gunzipSync(bytes));
    case "deflate":
      return new Uint8Array(inflateSync(bytes));
    default:
      return bytes;
  }
}

export function normalizeForensicRecord(raw: Record<string, unknown>, ruleNames?: Map<string, string>): ForensicRecord {
  const ruleId = str(raw.TriggeredRuleID);
  const contentType = headerValue(raw.Headers, "content-type");
  const contentEncoding = headerValue(raw.Headers, "content-encoding");

  let bodyText: string | null = null;
  let bodyTruncated = false;
  let decodeError: string | null = null;

  const payload = str(raw.Payload);
  if (payload) {
    try {
      const decoded = decompress(decodeBase64(payload), contentEncoding);
      const text = new TextDecoder("utf-8").decode(decoded);
      bodyTruncated = text.length > MAX_BODY_CHARS;
      bodyText = bodyTruncated ? text.slice(0, MAX_BODY_CHARS) : text;
    } catch (err) {
      decodeError = err instanceof Error ? err.message : String(err);
    }
  }

  const { Payload: _payload, ...rawWithoutPayload } = raw;

  return {
    timestampMs: parseTimeMs(raw.Datetime),
    forensicCopyId: str(raw.ForensicCopyID),
    gatewayRequestId: str(raw.GatewayRequestID),
    phase: str(raw.Phase) ?? "unknown",
    triggeredRuleId: ruleId,
    triggeredRuleName: (ruleId && ruleNames?.get(ruleId)) || ruleId,
    contentType,
    contentEncoding,
    bodyText,
    bodyTruncated,
    decodeError,
    raw: rawWithoutPayload,
  };
}
