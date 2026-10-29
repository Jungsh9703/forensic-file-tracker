export interface Env {
  /** R2 bucket both Logpush jobs write into, under separate prefixes. */
  LOGS_BUCKET: R2Bucket;

  /** R2 key prefix of the gateway_http Logpush job, e.g. "http/". */
  HTTP_LOG_PREFIX?: string;
  /** R2 key prefix of the DLP forensic copies Logpush job, e.g.
   * "forensic/". Its Payload is real request/response content (base64, not
   * encrypted -- see decode.ts), so treat everything derived from it as
   * sensitive. */
  FORENSIC_LOG_PREFIX?: string;

  /** Bearer token for GET /forensic/lookup and /forensic/file (lookup.ts).
   * Required, not optional: those endpoints return real uploaded file
   * contents, so they answer 503 until this is set. */
  LOOKUP_TOKEN?: string;
  /** Cap on R2 objects scanned per prefix per lookup request. */
  MAX_LOOKUP_OBJECTS?: string;
}
