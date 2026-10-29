import type { Env } from "./env";
import { handleApiRoutes } from "./api";
import dashboardHtml from "./dashboard.html";
import { runIngestion } from "./ingest";
import { handleForensicRoutes } from "./lookup";

/** The page itself holds no data -- it asks for LOOKUP_TOKEN and calls
 * /api/* with it -- so it's served without auth. The CSP keeps it from
 * talking to anything but this Worker. */
const DASHBOARD_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy":
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Step 3: dashboard page over the step 2 API.
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/dashboard")) {
      return new Response(dashboardHtml, { headers: DASHBOARD_HEADERS });
    }

    // Step 2: D1-backed queries (/api/transfers, /api/summary, /api/files, /api/status, /api/ingest).
    const api = await handleApiRoutes(request, env);
    if (api) return api;

    // Step 1 forensic file lookup straight from R2 (GatewayRequestID ->
    // decoded files -> filename by hash); token-gated, see lookup.ts.
    const forensic = await handleForensicRoutes(request, env);
    if (forensic) return forensic;

    return new Response("Not found", { status: 404 });
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
