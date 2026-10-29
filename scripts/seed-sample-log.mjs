// Generates small gzip NDJSON files shaped like real Cloudflare Logpush
// deliveries and drops them into the local R2 simulator that `wrangler dev`
// uses, so ingestion can be exercised end-to-end without real
// Cloudflare/Loki traffic. Field names (PascalCase) and shapes are copied
// from real objects downloaded directly from the Logpush-fed R2 bucket --
// NOT from Cloudflare's docs or the Zero Trust dashboard's log viewer, both
// of which describe a different (snake_case) schema belonging to a separate
// live-query API, not Logpush. Keys are written under HTTP_LOG_PREFIX /
// FORENSIC_LOG_PREFIX (see wrangler.toml) so runIngestion actually picks
// them up -- objects outside those prefixes are silently ignored.
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";

const nowMs = Date.now();

function iso(msAgo) {
  return new Date(nowMs - msAgo).toISOString();
}

function putObject(key, ndjson) {
  const gz = gzipSync(Buffer.from(ndjson, "utf8"));
  mkdirSync("scripts/.tmp", { recursive: true });
  const outPath = `scripts/.tmp/${key.replace(/\//g, "_")}`;
  writeFileSync(outPath, gz);
  console.log(`Writing ${key} ...`);
  execSync(`npx wrangler r2 object put sh-logpush-test/${key} --file="${outPath}" --local`, {
    stdio: "inherit",
  });
}

// --- gateway_http samples ---
const hosts = ["example.com", "internal-api.example", "docs.example", "cdn.example"];

const httpSamples = [
  { Action: "allow", HTTPStatusCode: 200, HTTPHost: hosts[0], URL: "https://example.com/", HTTPMethod: "GET" },
  { Action: "allow", HTTPStatusCode: 200, HTTPHost: hosts[1], URL: "https://internal-api.example/v1/orders", HTTPMethod: "GET" },
  { Action: "allow", HTTPStatusCode: 304, HTTPHost: hosts[2], URL: "https://docs.example/guide", HTTPMethod: "GET" },
  { Action: "block", HTTPStatusCode: 403, HTTPHost: "malware.test", URL: "https://malware.test/payload", HTTPMethod: "GET", PolicyID: "00000001-block-known-malware", PolicyName: "Block Known Malware" },
  { Action: "allow", HTTPStatusCode: 502, HTTPHost: "flaky-upstream.example", URL: "https://flaky-upstream.example/api", HTTPMethod: "POST" },
  { Action: "isolate", HTTPStatusCode: 200, HTTPHost: "risky-site.example", URL: "https://risky-site.example/", HTTPMethod: "GET", PolicyID: "00000002-isolate-risky-category", PolicyName: "Isolate Risky Category", IsIsolated: true },
  { Action: "allow", HTTPStatusCode: 200, HTTPHost: hosts[3], URL: "https://cdn.example/app.js", HTTPMethod: "GET" },
  { Action: "block", HTTPStatusCode: 403, HTTPHost: "social-media.example", URL: "https://social-media.example/feed", HTTPMethod: "GET", PolicyID: "00000003-block-social-media", PolicyName: "Block Social Media", CategoryIDs: [12], CategoryNames: ["Social Networking"] },
  { Action: "allow", HTTPStatusCode: 500, HTTPHost: hosts[1], URL: "https://internal-api.example/v1/reports", HTTPMethod: "GET" },
  { Action: "allow", HTTPStatusCode: 404, HTTPHost: hosts[0], URL: "https://example.com/missing", HTTPMethod: "GET" },
  // Exercises the DLP-match dashboard panels -- these arrays are the ones
  // that must survive as Loki-queryable scalars (see loki.ts's comment on
  // why they're JSON.stringify'd before being embedded in the log line).
  { Action: "allow", HTTPStatusCode: 200, HTTPHost: "chat.example", URL: "https://chat.example/api", HTTPMethod: "POST", UploadMatchedDlpProfiles: ["카드번호_DLP"] },
];

// --- File upload sample (exercises /forensic/lookup's hash matching) ---
// The browser sends the file as multipart part filename "blob" (common for
// JS-driven uploads), so the real name only comes from gateway_http's
// FileInfo -- matched by the file's SHA-256, not by the multipart name.
const uploadRequestId = "req-upload-0001";
const uploadFileName = "고객명단_2026.csv";
const uploadFileBytes = Buffer.from("이름,전화번호\n홍길동,010-0000-0000\n", "utf8");
const uploadFileSha256 = createHash("sha256").update(uploadFileBytes).digest("hex");
const uploadBoundary = "----SampleBoundary7MA4YWxk";
const uploadMultipart = Buffer.concat([
  Buffer.from(`--${uploadBoundary}\r\nContent-Disposition: form-data; name="folderId"\r\n\r\nroot\r\n`, "utf8"),
  Buffer.from(`--${uploadBoundary}\r\nContent-Disposition: form-data; name="file"; filename="blob"\r\nContent-Type: text/csv\r\n\r\n`, "utf8"),
  uploadFileBytes,
  Buffer.from(`\r\n--${uploadBoundary}--\r\n`, "utf8"),
]);

httpSamples.push({
  RequestID: uploadRequestId,
  Action: "allow",
  HTTPStatusCode: 200,
  HTTPHost: "upload.storage.example",
  URL: "https://upload.storage.example/api/v1/files",
  HTTPMethod: "POST",
  SourceIP: "203.0.113.10",
  DestinationIP: "198.51.100.20",
  UploadedFileNames: [uploadFileName],
  FileInfo: {
    files: [
      {
        file_name: uploadFileName,
        file_hash: uploadFileSha256,
        file_size: uploadFileBytes.length,
        content_type: "text/csv",
        direction: "upload",
        action: "allow",
      },
    ],
  },
});

const httpLines = httpSamples.map((s, idx) =>
  JSON.stringify({
    Datetime: iso((httpSamples.length - idx) * 1000),
    RequestID: `req-${String(idx + 1).padStart(4, "0")}`,
    Email: `user${(idx % 4) + 1}@example.com`,
    SourceIPCountryCode: "KR",
    DestinationIPCountryCode: "US",
    CategoryIDs: [],
    CategoryNames: [],
    ...s,
  }),
);
putObject(`http/sample-${nowMs}.log.gz`, httpLines.join("\n") + "\n");

// --- DLP forensic copies samples ---
// Payload is base64 -- NOT encrypted (see src/forensic.ts and the
// gateway-log-pipeline README). The "request" sample below decodes straight
// to plaintext JSON; the "response" sample is additionally gzip-compressed
// before being base64-encoded, to exercise the Content-Encoding-driven
// decompression path (real traffic often uses "br" instead -- gzip is used
// here only because Node's zlib can produce it inline without extra deps).
const forensicRequestBody = JSON.stringify({ prompt: "샘플 테스트 프롬프트입니다.", model: "claude-test", locale: "ko-KR" });
const forensicResponseBody = JSON.stringify({ type: "completion", content: "샘플 응답입니다." });

const forensicSamples = [
  {
    ForensicCopyID: "fc-req-0001",
    GatewayRequestID: "req-0001",
    Phase: "request",
    TriggeredRuleID: "00000009-dlp-rule-sample",
    Headers: { "content-type": "application/json" },
    Payload: Buffer.from(forensicRequestBody, "utf8").toString("base64"),
  },
  {
    ForensicCopyID: "fc-req-0002",
    GatewayRequestID: "req-0001",
    Phase: "response",
    TriggeredRuleID: "00000009-dlp-rule-sample",
    Headers: { "content-type": "text/event-stream", "content-encoding": "gzip" },
    Payload: gzipSync(Buffer.from(forensicResponseBody, "utf8")).toString("base64"),
  },
  {
    ForensicCopyID: "fc-upload-0001",
    GatewayRequestID: uploadRequestId,
    Phase: "request",
    TriggeredRuleID: "00000010-forensic-upload-sample",
    Headers: { "content-type": `multipart/form-data; boundary=${uploadBoundary}` },
    Payload: uploadMultipart.toString("base64"),
  },
];

const forensicLines = forensicSamples.map((s, idx) =>
  JSON.stringify({
    AccountID: "acct-sample",
    Datetime: iso((forensicSamples.length - idx) * 1000),
    ...s,
  }),
);
putObject(`forensic/sample-${nowMs}.log.gz`, forensicLines.join("\n") + "\n");

console.log("Done. Now trigger ingestion with: curl -X POST http://127.0.0.1:8787/run");
console.log(`File lookup: curl -H "Authorization: Bearer <LOOKUP_TOKEN>" "http://127.0.0.1:8787/forensic/lookup?request_id=${uploadRequestId}"`);
console.log(`Expected sha256: ${uploadFileSha256}`);
