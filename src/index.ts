import type { Env } from "./env";
import { handleApiRoutes } from "./api";
import { runIngestion } from "./ingest";
import { handleForensicRoutes } from "./lookup";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Step 2: D1-backed queries (/api/transfers, /api/files, /api/status, /api/ingest).
    const api = await handleApiRoutes(request, env);
    if (api) return api;

    // Step 1 forensic file lookup straight from R2 (GatewayRequestID ->
    // decoded files -> filename by hash); token-gated, see lookup.ts.
    const forensic = await handleForensicRoutes(request, env);
    if (forensic) return forensic;

    return new Response(
      "forensic-file-tracker: GET /api/transfers, /api/status, /forensic/lookup?request_id=<id> (Bearer LOOKUP_TOKEN).",
      { status: 200 },
    );
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        const summary = await runIngestion(env);
        console.log("forensic-file-tracker ingest", JSON.stringify(summary));
      })(),
    );
  },
} satisfies ExportedHandler<Env>;
