import { decodeBase64, decompress, headerValue, parseTimeMs } from "./decode";

/** One entry of gateway_http's FileInfo.files[]. Cloudflare's field
 * reference only says FileInfo is an "object" -- these keys come from a
 * third-party parser (Google SecOps' Cloudflare parser changelog, which maps
 * FileInfo.files.file_name/file_hash/file_size/content_type/direction/
 * action). Verify against one real record and adjust parseFileInfo if they
 * differ. */
export interface FileInfoEntry {
  fileName: string | null;
  fileHash: string | null;
  fileSize: number | null;
  contentType: string | null;
  direction: string | null;
  action: string | null;
}

export interface ExtractedFile {
  /** Filename from the multipart part's Content-Disposition, if any. */
  partFileName: string | null;
  contentType: string | null;
  bytes: Uint8Array;
  /** The part (or body) ended before its closing boundary -- the forensic
   * copy was cut off, so the hash won't match the real file. */
  truncated: boolean;
}

export interface ResolvedFile {
  fileName: string | null;
  /** Which evidence fileName came from, strongest first. */
  matchedBy: "hash" | "multipart" | "uploaded_file_names" | "none";
  sha256: string;
  size: number;
  contentType: string | null;
  truncated: boolean;
  fileInfoMatch: FileInfoEntry | null;
}

export interface DecodedCopy {
  datetime: string;
  timestampMs: number;
  forensicCopyId: string | null;
  gatewayRequestId: string | null;
  phase: string | null;
  triggeredRuleId: string | null;
  headers: Record<string, unknown>;
  contentType: string | null;
  contentEncoding: string | null;
  decodeError: string | null;
  /** Decoded (and decompressed) Payload bytes -- null if missing/undecodable. */
  body: Uint8Array | null;
  files: ExtractedFile[];
}

const enc = new TextEncoder();

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))) return Number(v);
  return null;
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array, from = 0): number {
  const first = needle[0];
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    if (hay[i] !== first) continue;
    for (let j = 1; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function multipartBoundary(contentType: string): string | null {
  const m = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  return m ? (m[1] ?? m[2] ?? null) : null;
}

/** RFC 6266/5987: prefer filename*=UTF-8''<pct-encoded> over filename="...". */
function dispositionFileName(disposition: string): string | null {
  const ext = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(disposition);
  if (ext?.[2]) {
    try {
      return decodeURIComponent(ext[2].trim());
    } catch {
      /* fall through to plain filename */
    }
  }
  const plain = /filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]+))/i.exec(disposition);
  const v = plain?.[1] ?? plain?.[2];
  return v !== undefined ? v.replace(/\\(.)/g, "$1").trim() : null;
}

/**
 * Byte-level multipart/form-data parser. Deliberately not Response.formData():
 * forensic copies can be truncated mid-upload, and formData() just throws on
 * a missing closing boundary -- here we keep the partial part (flagged
 * truncated) so at least the filename survives. Only parts with a filename
 * are returned; plain form fields are skipped.
 */
export function parseMultipartFiles(body: Uint8Array, contentType: string): ExtractedFile[] {
  const boundary = multipartBoundary(contentType);
  if (!boundary) return [];
  const delim = enc.encode(`--${boundary}`);
  const crlfcrlf = enc.encode("\r\n\r\n");
  const files: ExtractedFile[] = [];

  let pos = indexOfBytes(body, delim);
  while (pos !== -1) {
    let start = pos + delim.length;
    // "--" right after a delimiter marks the end of the multipart body.
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break;
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;

    const next = indexOfBytes(body, delim, start);
    const truncated = next === -1;
    // Part content ends at the CRLF that precedes the next delimiter.
    let end = truncated ? body.length : next;
    if (!truncated && body[end - 2] === 0x0d && body[end - 1] === 0x0a) end -= 2;

    const headerEnd = indexOfBytes(body.subarray(start, end), crlfcrlf);
    if (headerEnd !== -1) {
      const headerText = new TextDecoder("utf-8").decode(body.subarray(start, start + headerEnd));
      const headers = new Map<string, string>();
      for (const line of headerText.split("\r\n")) {
        const idx = line.indexOf(":");
        if (idx > 0) headers.set(line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim());
      }
      const disposition = headers.get("content-disposition") ?? "";
      const partFileName = dispositionFileName(disposition);
      if (partFileName !== null) {
        files.push({
          partFileName,
          contentType: headers.get("content-type") ?? null,
          bytes: body.slice(start + headerEnd + crlfcrlf.length, end),
          truncated,
        });
      }
    }
    if (truncated) break;
    pos = next;
  }
  return files;
}

/** Request bodies that are clearly not a file upload (API calls, chat
 * prompts, form posts) -- everything else non-multipart is treated as one
 * raw file body (e.g. PUT-style or resumable uploads). */
function isTextualBody(contentType: string | null): boolean {
  const ct = (contentType ?? "").toLowerCase();
  return (
    ct === "" ||
    ct.startsWith("text/") ||
    ct.includes("json") ||
    ct.includes("xml") ||
    ct.includes("x-www-form-urlencoded") ||
    ct.includes("graphql") ||
    ct.includes("grpc") ||
    ct.includes("protobuf")
  );
}

export function decodeForensicCopy(raw: Record<string, unknown>): DecodedCopy {
  const headers = raw.Headers && typeof raw.Headers === "object" ? (raw.Headers as Record<string, unknown>) : {};
  const contentType = headerValue(headers, "content-type");
  const contentEncoding = headerValue(headers, "content-encoding");
  const phase = str(raw.Phase);
  const timestampMs = parseTimeMs(raw.Datetime);

  let body: Uint8Array | null = null;
  let decodeError: string | null = null;
  const payload = str(raw.Payload);
  if (payload) {
    try {
      body = decompress(decodeBase64(payload), contentEncoding);
    } catch (err) {
      decodeError = err instanceof Error ? err.message : String(err);
    }
  }

  let files: ExtractedFile[] = [];
  if (body && phase === "request") {
    if ((contentType ?? "").toLowerCase().startsWith("multipart/form-data")) {
      files = parseMultipartFiles(body, contentType!);
    } else if (!isTextualBody(contentType) && body.length > 0) {
      files = [{ partFileName: null, contentType, bytes: body, truncated: false }];
    }
  }

  return {
    datetime: new Date(timestampMs).toISOString(),
    timestampMs,
    forensicCopyId: str(raw.ForensicCopyID),
    gatewayRequestId: str(raw.GatewayRequestID),
    phase,
    triggeredRuleId: str(raw.TriggeredRuleID),
    headers,
    contentType,
    contentEncoding,
    decodeError,
    body,
    files,
  };
}

/** FileInfo has been seen documented only as "object"; accept it either
 * parsed or as a JSON string, with the entries under .files. */
export function parseFileInfo(v: unknown): FileInfoEntry[] {
  let obj: unknown = v;
  if (typeof v === "string") {
    try {
      obj = JSON.parse(v);
    } catch {
      return [];
    }
  }
  const files = obj && typeof obj === "object" ? (obj as Record<string, unknown>).files : undefined;
  if (!Array.isArray(files)) return [];
  return files
    .filter((f): f is Record<string, unknown> => !!f && typeof f === "object")
    .map((f) => ({
      fileName: str(f.file_name),
      fileHash: str(f.file_hash)?.toLowerCase() ?? null,
      fileSize: num(f.file_size),
      contentType: str(f.content_type),
      direction: str(f.direction),
      action: str(f.action),
    }));
}

async function digestHex(algo: string, bytes: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest(algo, bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return digestHex("SHA-256", bytes);
}

/** FileInfo.file_hash's algorithm isn't documented -- infer it from length
 * and compute the matching digest (Workers' WebCrypto supports MD5 too). */
const ALGO_BY_HEX_LENGTH: Record<number, string> = { 64: "SHA-256", 40: "SHA-1", 32: "MD5" };

/**
 * Settles each extracted file's name: FileInfo entry whose file_hash equals
 * the file's own digest first (strongest -- ties Cloudflare's own file
 * detection to the bytes we actually hold), then the multipart filename,
 * then UploadedFileNames by position.
 */
export async function resolveFiles(
  files: ExtractedFile[],
  fileInfo: FileInfoEntry[],
  uploadedFileNames: string[],
): Promise<ResolvedFile[]> {
  const out: ResolvedFile[] = [];
  for (const [idx, f] of files.entries()) {
    const digests = new Map<string, string>();
    const sha256 = await sha256Hex(f.bytes);
    digests.set("SHA-256", sha256);

    let match: FileInfoEntry | null = null;
    for (const entry of fileInfo) {
      const algo = entry.fileHash ? ALGO_BY_HEX_LENGTH[entry.fileHash.length] : undefined;
      if (!algo) continue;
      if (!digests.has(algo)) digests.set(algo, await digestHex(algo, f.bytes));
      if (digests.get(algo) === entry.fileHash) {
        match = entry;
        break;
      }
    }

    let fileName: string | null = null;
    let matchedBy: ResolvedFile["matchedBy"] = "none";
    if (match?.fileName) {
      fileName = match.fileName;
      matchedBy = "hash";
    } else if (f.partFileName) {
      fileName = f.partFileName;
      matchedBy = "multipart";
    } else if (uploadedFileNames[idx]) {
      fileName = uploadedFileNames[idx]!;
      matchedBy = "uploaded_file_names";
    }

    out.push({
      fileName,
      matchedBy,
      sha256,
      size: f.bytes.length,
      contentType: f.contentType,
      truncated: f.truncated,
      fileInfoMatch: match,
    });
  }
  return out;
}
