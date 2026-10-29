import type { Env } from "./env";
import { getNamedCache, saveNamedCache } from "./cursor";

const CACHE_KEY = "dlp-profile-names";
// Same rationale as policy_names.ts: profiles rarely change, so avoid
// refetching every 1-minute cron run.
const CACHE_TTL_MS = 30 * 60 * 1000;

interface DlpProfileEntry {
  id?: string;
  name?: string;
}

interface DlpProfile {
  id?: string;
  name?: string;
  entries?: DlpProfileEntry[];
}

/**
 * Fetches both DLP profile names AND their individual entry names into one
 * flat id->name map, since gateway_http's *_dlp_profiles and
 * *_dlp_profileEntries fields are both plain UUID arrays with no way to
 * tell which is which from the ID alone -- a single combined lookup covers
 * both. The exact shape of a profile's `entries` array is unconfirmed
 * against a real API response (Cloudflare's docs pages didn't render a full
 * example for this session) -- verify against a real response and adjust
 * if entry names don't show up.
 */
async function fetchDlpNamesFromApi(env: Env): Promise<Record<string, string>> {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/dlp/profiles`, {
    headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Cloudflare DLP profiles API failed: ${res.status} ${body.slice(0, 300)}`);
  }
  const data = (await res.json()) as { result?: DlpProfile[] };
  const names: Record<string, string> = {};
  for (const profile of data.result ?? []) {
    if (profile.id && profile.name) names[profile.id] = profile.name;
    for (const entry of profile.entries ?? []) {
      if (entry.id && entry.name) names[entry.id] = entry.name;
    }
  }
  return names;
}

/**
 * Resolves DLP profile/profile-entry IDs (gateway_http's
 * *_matched_dlp_profiles / *_matched_dlp_profileEntries fields) to their
 * human-readable names via the Cloudflare API. Returns an empty map --
 * callers fall back to the raw ID -- if CF_ACCOUNT_ID/CF_API_TOKEN aren't
 * configured or the API call fails; this must never block ingestion.
 */
export async function getDlpNameMap(env: Env): Promise<Map<string, string>> {
  if (!env.CF_ACCOUNT_ID || !env.CF_API_TOKEN) return new Map();

  const cached = await getNamedCache(env, CACHE_KEY);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return new Map(Object.entries(cached.names));
  }

  try {
    const names = await fetchDlpNamesFromApi(env);
    await saveNamedCache(env, CACHE_KEY, { names, fetchedAt: Date.now() });
    return new Map(Object.entries(names));
  } catch (err) {
    console.warn("gateway-log-pipeline: failed to refresh DLP profile name cache", err);
    return cached ? new Map(Object.entries(cached.names)) : new Map();
  }
}
