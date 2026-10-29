/**
 * Decrypts the encrypted blobs Cloudflare embeds in gateway_http logs --
 * both "Capture generative AI prompt content in logs" (gen_ai_prompt_*
 * fields) and DLP payload/matched-data logging (dlp_match_context_parsed.p
 * entries). Both use the same HPKE (RFC 9180) scheme, keyed to the
 * account's DLP payload encryption key pair (Zero Trust dashboard ->
 * Settings -> DLP -> DLP Payload Encryption public key). Ported from
 * ../../workers (AI Prompt Log Dashboard), which mirrors Cloudflare's own
 * reference tool (github.com/cloudflare/matched-data-worker):
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305, framed as
 * [1 byte version=3][32 byte encapsulated key][8 byte length][ciphertext].
 */
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

const FRAME_VERSION = 3;
const ENCAPPED_KEY_LEN = 32;
const LENGTH_PREFIX_LEN = 8;
const HEADER_LEN = 1 + ENCAPPED_KEY_LEN + LENGTH_PREFIX_LEN;

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

export interface DecryptResult {
  ok: boolean;
  plaintext?: string;
  error?: string;
}

function b64ToBuf(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

interface Frame {
  encappedKey: ArrayBuffer;
  payload: ArrayBuffer;
}

function parseFrame(buf: ArrayBuffer): Frame | null {
  if (buf.byteLength <= HEADER_LEN) return null;
  const version = new Uint8Array(buf, 0, 1)[0];
  if (version !== FRAME_VERSION) return null;
  return {
    encappedKey: buf.slice(1, 1 + ENCAPPED_KEY_LEN),
    payload: buf.slice(HEADER_LEN),
  };
}

let cachedKey: { raw: string; key: CryptoKey } | null = null;

async function importPrivateKey(privateKeyBase64: string): Promise<CryptoKey> {
  if (cachedKey && cachedKey.raw === privateKeyBase64) {
    return cachedKey.key;
  }
  const key = await suite.kem.importKey("raw", b64ToBuf(privateKeyBase64));
  cachedKey = { raw: privateKeyBase64, key };
  return key;
}

/**
 * Decrypts a single base64-encoded, HPKE-framed blob using the account's
 * DLP payload encryption private key.
 */
export async function decryptPayload(base64Payload: string, privateKeyBase64: string): Promise<DecryptResult> {
  const frame = parseFrame(b64ToBuf(base64Payload));
  if (!frame) {
    return { ok: false, error: "unrecognized frame (expected HPKE version 3)" };
  }
  try {
    const recipientKey = await importPrivateKey(privateKeyBase64);
    const recipient = await suite.createRecipientContext({
      recipientKey,
      enc: frame.encappedKey,
    });
    const plaintext = await recipient.open(frame.payload);
    return { ok: true, plaintext: new TextDecoder().decode(plaintext) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
