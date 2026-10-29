export interface LogRecord {
  timestampMs: number;
  requestId: string | null;
  action: string;
  statusCode: number | null;
  method: string | null;
  policyId: string | null;
  policyName: string | null;
  host: string | null;
  url: string | null;
  identity: string | null;
  isIsolated: boolean;
  srcCountry: string | null;
  dstCountry: string | null;
  categoryIds: number[];
  /** Cloudflare ships these pre-resolved (unlike DLP profile IDs) -- no API
   * lookup needed. */
  categoryNames: string[];
  /** Resolved via dlpNames (Cloudflare API, see dlp_profile_names.ts) where
   * possible; otherwise the raw UUID -- Logpush has no name field for these. */
  uploadDlpProfiles: string[];
  downloadDlpProfiles: string[];
  uploadDlpProfileEntries: string[];
  downloadDlpProfileEntries: string[];
  /** Decrypted separately in ingest.ts (see dlp.ts) -- normalizeRecord
   * always initializes these to null since it's synchronous. As of writing,
   * the gateway_http Logpush dataset doesn't appear to include any field
   * for GenAI prompt capture or DLP matched-data context at all (confirmed
   * against a real delivered object's full field list), so these likely
   * stay null regardless of DLP_PRIVATE_KEY -- see dlp.ts's comment. */
  genAiPromptRequest: string | null;
  genAiPromptResponse: string | null;
  genAiConversation: string | null;
  dlpMatchedContext: Record<string, string> | null;
  /** Full original log record, so nothing is dropped on the way in --
   * Loki (backed by Azure Blob) is the only durable store here. */
  raw: Record<string, unknown>;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) return Number(v);
  return null;
}

function numArray(v: unknown): number[] {
  return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
}

function strArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}

function resolveIdArray(v: unknown, names?: Map<string, string>): string[] {
  return strArray(v).map((id) => names?.get(id) ?? id);
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

/**
 * Normalizes every gateway_http log line -- never filters anything out;
 * every line that parses as JSON becomes one record.
 *
 * Field names are **PascalCase** -- confirmed against a real object
 * downloaded directly from the R2 bucket the Logpush job writes to (Action,
 * PolicyID, PolicyName, HTTPHost, HTTPMethod, HTTPStatusCode, Email,
 * UserID, RequestID, IsIsolated, SourceIPCountryCode,
 * DestinationIPCountryCode, CategoryIDs, CategoryNames,
 * Upload/DownloadMatchedDlpProfiles(Entries), Datetime as an RFC3339
 * string). This matches Cloudflare's documented Logpush field reference and
 * the "Configure logpush job" field picker -- NOT the snake_case shape the
 * Zero Trust dashboard's own "HTTP request logs" viewer shows, which is a
 * completely separate live-query API with its own schema and is NOT what
 * ends up in R2. PolicyName is blank for some traffic/policy types in
 * practice (e.g. "bypass" traffic under a system policy like "Do Not
 * Inspect" omits it along with several other HTTP-specific fields) --
 * policyNames (the API-resolved fallback, see policy_names.ts) covers
 * exactly that gap.
 */
export function normalizeRecord(
  raw: Record<string, unknown>,
  policyNames?: Map<string, string>,
  dlpNames?: Map<string, string>,
): LogRecord {
  const policyId = str(raw.PolicyID);

  return {
    timestampMs: parseTimeMs(raw.Datetime),
    requestId: str(raw.RequestID),
    action: str(raw.Action) ?? "unknown",
    statusCode: num(raw.HTTPStatusCode),
    method: str(raw.HTTPMethod),
    policyId,
    policyName: str(raw.PolicyName) || (policyId && policyNames?.get(policyId)) || policyId,
    host: str(raw.HTTPHost),
    url: str(raw.URL),
    identity: str(raw.Email) || str(raw.UserID),
    isIsolated: raw.IsIsolated === true,
    srcCountry: str(raw.SourceIPCountryCode),
    dstCountry: str(raw.DestinationIPCountryCode),
    categoryIds: numArray(raw.CategoryIDs),
    categoryNames: strArray(raw.CategoryNames),
    uploadDlpProfiles: resolveIdArray(raw.UploadMatchedDlpProfiles, dlpNames),
    downloadDlpProfiles: resolveIdArray(raw.DownloadMatchedDlpProfiles, dlpNames),
    uploadDlpProfileEntries: resolveIdArray(raw.UploadMatchedDlpProfileEntries, dlpNames),
    downloadDlpProfileEntries: resolveIdArray(raw.DownloadMatchedDlpProfileEntries, dlpNames),
    genAiPromptRequest: null,
    genAiPromptResponse: null,
    genAiConversation: null,
    dlpMatchedContext: null,
    raw,
  };
}
