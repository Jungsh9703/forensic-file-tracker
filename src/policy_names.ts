import type { Env } from "./env";
import { getNamedCache, saveNamedCache } from "./cursor";

const CACHE_KEY = "policy-names";
// Policies rarely change; refetching the full rule list every 1-minute cron
// run would be wasteful, so the mapping is cached in the shared Durable
// Object and only refreshed once this TTL elapses.
const CACHE_TTL_MS = 30 * 60 * 1000;

interface GatewayRule {
  id?: string;
  name?: string;
}

async function fetchPolicyNamesFromApi(env: Env): Promise<Record<string, string>> {
  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/gateway/rules`, {
    headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Cloudflare Gateway rules API failed: ${res.status} ${body.slice(0, 300)}`);
  }
  const data = (await res.json()) as { result?: GatewayRule[] };
  const names: Record<string, string> = {};
  for (const rule of data.result ?? []) {
    if (rule.id && rule.name) names[rule.id] = rule.name;
  }
  return names;
}

/**
 * Resolves Gateway policy IDs (gateway_http's rule_id field) to their
 * human-readable names via the Cloudflare API -- the raw log has no name
 * field for this at all, so it's an enrichment step, not something
 * normalize.ts can get from the log alone. Returns an empty map -- callers
 * fall back to the raw rule_id -- if CF_ACCOUNT_ID/CF_API_TOKEN aren't
 * configured or the API call fails; this must never block ingestion.
 */
export async function getPolicyNameMap(env: Env): Promise<Map<string, string>> {
  if (!env.CF_ACCOUNT_ID || !env.CF_API_TOKEN) return new Map();

  const cached = await getNamedCache(env, CACHE_KEY);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return new Map(Object.entries(cached.names));
  }

  try {
    const names = await fetchPolicyNamesFromApi(env);
    await saveNamedCache(env, CACHE_KEY, { names, fetchedAt: Date.now() });
    return new Map(Object.entries(names));
  } catch (err) {
    console.warn("gateway-log-pipeline: failed to refresh policy name cache", err);
    return cached ? new Map(Object.entries(cached.names)) : new Map();
  }
}
