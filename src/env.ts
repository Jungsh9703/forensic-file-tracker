import type { IngestCursor } from "./cursor_do";

export interface Env {
  RAW_LOGS_BUCKET: R2Bucket;
  CURSOR_DO: DurableObjectNamespace<IngestCursor>;

  MAX_OBJECTS_PER_RUN: string;
  MAX_LINES_PER_OBJECT_RUN: string;
  COMPLETED_SET_CAP: string;

  /** R2 key prefix the gateway_http Logpush job writes under, e.g. "http/".
   * One bucket serves both this job and the forensic copies job below via
   * separate prefixes instead of needing two buckets. */
  HTTP_LOG_PREFIX?: string;
  /** R2 key prefix the "DLP forensic copies" Logpush job writes under, e.g.
   * "forensic/". Unlike gateway_http, this dataset's Payload field carries
   * the actual (base64-encoded, sometimes gzip/br-compressed -- NOT
   * encrypted, see forensic.ts) request/response body content a DLP rule
   * matched against. Treat this stream/dashboard as more sensitive than the
   * http traffic one -- it's real request/response content, not metadata. */
  FORENSIC_LOG_PREFIX?: string;

  /** Loki push API endpoint on the Azure VM. Must be a hostname, not a bare
   * IP -- Workers' fetch() routes IP-literal URLs through Cloudflare's edge
   * and gets back its own "error code: 1003" instead of ever reaching the
   * VM. With no real domain, use nip.io: e.g.
   * http://<vm-public-ip>.nip.io:3100/loki/api/v1/push */
  LOKI_URL: string;

  /** Basic Auth pair for Loki's nginx proxy. USERNAME is a plain var (not
   * sensitive); API_KEY is a secret. Both optional -- unset skips this auth
   * path entirely (e.g. if using CF_ACCESS_* instead). */
  LOKI_USERNAME?: string;
  LOKI_API_KEY?: string;

  /** Optional Cloudflare Access Service Token pair, if the Loki push
   * endpoint is fronted by a Cloudflare Tunnel + Access application. */
  CF_ACCESS_CLIENT_ID?: string;
  CF_ACCESS_CLIENT_SECRET?: string;

  /** Optional shared secret gating the manual POST /run test endpoint. */
  RUN_TOKEN?: string;

  /** Bearer token for GET /forensic/lookup and /forensic/file (lookup.ts).
   * Required, not optional: those endpoints return real uploaded file
   * contents, so they answer 503 until this is set. */
  LOOKUP_TOKEN?: string;
  /** Cap on R2 objects scanned per prefix per lookup request. */
  MAX_LOOKUP_OBJECTS?: string;

  /** Account ID for the Zero Trust Gateway Rules API (not sensitive -- it's
   * visible in the dashboard URL, hence a plain var). Paired with
   * CF_API_TOKEN to resolve gateway_http's rule_id to a human-readable
   * name -- the raw log has no name field for it at all. Both optional --
   * unset just falls back to showing the raw rule_id. */
  CF_ACCOUNT_ID?: string;
  /** API token with Account > Zero Trust > Read permission. */
  CF_API_TOKEN?: string;

  /** DLP Payload Encryption private key (base64, X25519), from Zero Trust
   * dashboard -> Settings -> DLP -> DLP Payload Encryption public key.
   * Decrypts gen_ai_prompt_request/response/conversation and DLP matched-
   * data context -- see dlp.ts and crypto.ts. Optional: unset just leaves
   * those fields null (the encrypted blob still ships inside `raw`). */
  DLP_PRIVATE_KEY?: string;
  /** Cap on HPKE decrypt operations per cron run, shared across all matched
   * lines -- each is a real ECDH + AEAD op, so a burst of matches in one
   * run shouldn't blow the Workers CPU budget. */
  MAX_DECRYPTIONS_PER_RUN: string;
}
