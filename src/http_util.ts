import type { Env } from "./env";

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

/** Every data endpoint returns real uploaded content or who-sent-what, so
 * they all refuse to run without LOOKUP_TOKEN configured. Bearer header,
 * not a query param, so the token doesn't end up in access logs. Returns
 * an error Response, or null when authorized. */
export function authorize(request: Request, env: Env): Response | null {
  if (!env.LOOKUP_TOKEN) return json({ error: "LOOKUP_TOKEN is not configured" }, 503);
  const given = (request.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  const a = new TextEncoder().encode(given);
  const b = new TextEncoder().encode(env.LOOKUP_TOKEN);
  if (a.byteLength !== b.byteLength || !crypto.subtle.timingSafeEqual(a, b)) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null;
}

/** RFC 6266 filename + filename* so non-ASCII (e.g. Korean) names survive. */
export function attachmentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

/** Extracted files are arbitrary user uploads (could be HTML/JS) -- always
 * an octet-stream download, never rendered inline. */
export function fileDownload(bytes: Uint8Array | ReadableStream, name: string, extra: Record<string, string> = {}): Response {
  return new Response(bytes, {
    headers: {
      "content-type": "application/octet-stream",
      "content-disposition": attachmentDisposition(name),
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
      ...extra,
    },
  });
}
