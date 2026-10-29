import { DurableObject } from "cloudflare:workers";

export interface ObjectCursor {
  nextLine: number;
  totalLines: number;
}

const COMPLETED_SET_KEY = "completed-set";

export interface NamedCache {
  names: Record<string, string>;
  fetchedAt: number;
}

/**
 * Holds the ingestion cursor state as a single global instance (see
 * cursor.ts's SINGLETON_ID_NAME). Durable Object storage is strongly
 * consistent with no propagation delay, unlike Workers KV (which is
 * eventually consistent, with writes taking up to ~60s to reach every edge
 * location) -- that matters once the cron runs every minute instead of
 * every 5, since a KV read shortly after a KV write could otherwise see
 * stale cursor data and reprocess or skip objects.
 */
export class IngestCursor extends DurableObject {
  async getCompletedSet(): Promise<string[]> {
    return (await this.ctx.storage.get<string[]>(COMPLETED_SET_KEY)) ?? [];
  }

  async saveCompletedSet(keys: string[], cap: number): Promise<void> {
    const trimmed = keys.length > cap ? keys.slice(keys.length - cap) : keys;
    await this.ctx.storage.put(COMPLETED_SET_KEY, trimmed);
  }

  async getObjectCursor(key: string): Promise<ObjectCursor | null> {
    return (await this.ctx.storage.get<ObjectCursor>(`cursor:${key}`)) ?? null;
  }

  async putObjectCursor(key: string, cursor: ObjectCursor): Promise<void> {
    await this.ctx.storage.put(`cursor:${key}`, cursor);
  }

  async deleteObjectCursor(key: string): Promise<void> {
    await this.ctx.storage.delete(`cursor:${key}`);
  }

  /** Generic id->name lookup cache, shared by policy_names.ts,
   * dlp_profile_names.ts, and any future Cloudflare-API-backed resolver --
   * keyed by an arbitrary cacheKey (e.g. "policy-names", "dlp-profile-names")
   * so each resolver gets its own independently-TTL'd slot. */
  async getNamedCache(cacheKey: string): Promise<NamedCache | null> {
    return (await this.ctx.storage.get<NamedCache>(`named-cache:${cacheKey}`)) ?? null;
  }

  async saveNamedCache(cacheKey: string, cache: NamedCache): Promise<void> {
    await this.ctx.storage.put(`named-cache:${cacheKey}`, cache);
  }
}
