import type { Env } from "./env";
import { runIngestion } from "./ingest";
import { handleForensicRoutes } from "./lookup";

// Durable Object classes must be exported from the Worker's main module for
// wrangler to find the class named in wrangler.toml's durable_objects.bindings.
export { IngestCursor } from "./cursor_do";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Step 1 forensic file lookup (GatewayRequestID -> decoded files ->
    // filename by hash); token-gated, see lookup.ts.
    const forensic = await handleForensicRoutes(request, env);
    if (forensic) return forensic;

    // Manual trigger so a run can be exercised without waiting for the cron
    // schedule, e.g. during local testing. If RUN_TOKEN is set it must match;
    // leave it unset only for local `wrangler dev` use.
    if (url.pathname === "/run" && request.method === "POST") {
      if (env.RUN_TOKEN && url.searchParams.get("token") !== env.RUN_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }
      const summary = await runIngestion(env);
      return new Response(JSON.stringify(summary, null, 2), {
        headers: { "content-type": "application/json" },
      });
    }

    return new Response("gateway-log-pipeline: POST /run to trigger manually, otherwise runs on cron.", {
      status: 200,
    });
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      (async () => {
        const summary = await runIngestion(env);
        console.log("gateway-log-pipeline run", JSON.stringify(summary));
      })(),
    );
  },
} satisfies ExportedHandler<Env>;
