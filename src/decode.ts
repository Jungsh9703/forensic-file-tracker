import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

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
 * DLP Forensic Copies are NOT encrypted -- Payload is just base64, and for
 * compressed bodies (e.g. Content-Encoding: br on streamed responses) the
 * bytes underneath are plain gzip/deflate/brotli, decodable with no key.
 * Confirmed against real sample records: a "request"-phase Payload decodes
 * directly to readable JSON; a "response"-phase Payload's apparent
 * randomness was explained entirely by its own Headers.content-encoding: br.
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

/** Parses a Cloudflare log timestamp (RFC3339 or epoch in s/ms/us/ns) into epoch ms. */
export function parseTimeMs(value: unknown): number {
  if (value === null || value === undefined) return Date.now();
  const asNumber = typeof value === "number" ? value : Number(value);
  if (!Number.isNaN(asNumber) && String(value).trim() !== "") {
    if (asNumber > 1e18) return Math.round(asNumber / 1e6); // ns -> ms
    if (asNumber > 1e15) return Math.round(asNumber / 1e3); // us -> ms
    if (asNumber > 1e12) return Math.round(asNumber); // already ms
    if (asNumber > 1e9) return Math.round(asNumber * 1000); // seconds -> ms
  }
  const parsed = Date.parse(String(value));
  return Number.isNaN(parsed) ? Date.now() : parsed;
}
