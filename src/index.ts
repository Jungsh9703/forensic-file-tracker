import type { Env } from "./env";
import { handleForensicRoutes } from "./lookup";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Step 1 forensic file lookup (GatewayRequestID -> decoded files ->
    // filename by hash); token-gated, see lookup.ts.
    const forensic = await handleForensicRoutes(request, env);
    if (forensic) return forensic;

    return new Response("forensic-file-tracker: GET /forensic/lookup?request_id=<id> (Bearer LOOKUP_TOKEN).", {
      status: 200,
    });
  },
} satisfies ExportedHandler<Env>;
