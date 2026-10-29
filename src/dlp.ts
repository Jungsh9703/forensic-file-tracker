import type { Env } from "./env";
import { decryptPayload } from "./crypto";

export interface DecryptedFields {
  genAiPromptRequest: string | null;
  genAiPromptResponse: string | null;
  genAiConversation: string | null;
  /** Decrypted context snippets from dlp_match_context_parsed.p, keyed by
   * their original index -- entries that fail to decrypt (wrong/rotated
   * key, budget exhausted) are simply omitted, not replaced with an error
   * string, since the raw encrypted blob is still preserved in `raw`. */
  dlpMatchedContext: Record<string, string> | null;
}

export const NO_DECRYPTED_FIELDS: DecryptedFields = {
  genAiPromptRequest: null,
  genAiPromptResponse: null,
  genAiConversation: null,
  dlpMatchedContext: null,
};

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

interface DlpMatchContextParsed {
  p?: Record<string, { k?: string; p?: string }>;
}

/**
 * Decrypts whatever encrypted content is present on one raw gateway_http
 * record: "Capture generative AI prompt content in logs"
 * (GenAiPromptRequest/Response/Conversation) and DLP matched-data context
 * (DlpMatchContextParsed.p entries) -- both use the same HPKE scheme (see
 * crypto.ts). Spends from a shared per-run budget, since each decrypt is a
 * real ECDH + AEAD operation and a burst of matched lines in one 1-minute
 * cron run shouldn't blow the Workers CPU budget. Lines skipped for budget
 * aren't lost -- `raw` (the full original record) ships to Loki regardless,
 * encrypted blob and all, so nothing is unrecoverable.
 *
 * CAVEAT: a real object downloaded directly from the Logpush-fed R2 bucket
 * enumerated ~60 gateway_http fields and included none of the four this
 * function looks for -- Logpush's gateway_http dataset may simply not
 * export GenAI prompt capture or DLP matched-data content at all (only
 * Cloudflare's own Zero Trust dashboard log viewer -- a separate live-query
 * API, not Logpush -- appears to expose them, e.g. via its "Decrypt payload
 * log" button). Left in place (checking both likely casings) in case a
 * differently-configured Logpush job, a DLP-triggered record, or a future
 * Cloudflare change does include them; this just no-ops otherwise.
 */
export async function decryptFields(
  raw: Record<string, unknown>,
  env: Env,
  budget: { remaining: number },
): Promise<DecryptedFields> {
  const privateKey = env.DLP_PRIVATE_KEY;
  if (!privateKey) return NO_DECRYPTED_FIELDS;

  const genAiPromptRequest = str(raw.GenAiPromptRequest) ?? str(raw.gen_ai_prompt_request);
  const genAiPromptResponse = str(raw.GenAiPromptResponse) ?? str(raw.gen_ai_prompt_response);
  const genAiConversation = str(raw.GenAiConversation) ?? str(raw.gen_ai_conversation);
  const dlpContext = (raw.DlpMatchContextParsed ?? raw.dlp_match_context_parsed) as
    | DlpMatchContextParsed
    | null
    | undefined;
  const dlpEntries = Object.entries(dlpContext?.p ?? {}).filter(
    (entry): entry is [string, { p: string }] => typeof entry[1]?.p === "string",
  );

  if (!genAiPromptRequest && !genAiPromptResponse && !genAiConversation && dlpEntries.length === 0) {
    return NO_DECRYPTED_FIELDS;
  }

  const decryptIfBudget = async (blob: string | null): Promise<string | null> => {
    if (!blob || budget.remaining <= 0) return null;
    budget.remaining--;
    const result = await decryptPayload(blob, privateKey);
    return result.ok ? (result.plaintext ?? null) : null;
  };

  const [genAiPromptRequestDec, genAiPromptResponseDec, genAiConversationDec] = await Promise.all([
    decryptIfBudget(genAiPromptRequest),
    decryptIfBudget(genAiPromptResponse),
    decryptIfBudget(genAiConversation),
  ]);

  let dlpMatchedContext: Record<string, string> | null = null;
  for (const [key, entry] of dlpEntries) {
    const plaintext = await decryptIfBudget(entry.p);
    if (plaintext) {
      dlpMatchedContext ??= {};
      dlpMatchedContext[key] = plaintext;
    }
  }

  return {
    genAiPromptRequest: genAiPromptRequestDec,
    genAiPromptResponse: genAiPromptResponseDec,
    genAiConversation: genAiConversationDec,
    dlpMatchedContext,
  };
}
