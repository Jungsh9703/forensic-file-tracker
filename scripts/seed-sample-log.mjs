// Writes small gzip NDJSON files shaped like real Logpush deliveries into
// the local R2 simulator `wrangler dev` uses, so /forensic/lookup can be
// exercised without real traffic. Field names are PascalCase, as Logpush
// actually writes them to R2. Keys go under the same prefixes as
// wrangler.toml's HTTP_LOG_PREFIX / FORENSIC_LOG_PREFIX.
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { execSync } from "node:child_process";

const BUCKET = "sh-logpush-test";
const nowMs = Date.now();

function iso(msAgo) {
  return new Date(nowMs - msAgo).toISOString();
}

function putObject(key, lines) {
  const gz = gzipSync(Buffer.from(lines.map((l) => JSON.stringify(l)).join("\n") + "\n", "utf8"));
  mkdirSync("scripts/.tmp", { recursive: true });
  const outPath = `scripts/.tmp/${key.replace(/\//g, "_")}`;
  writeFileSync(outPath, gz);
  console.log(`Writing ${key} ...`);
  execSync(`npx wrangler r2 object put ${BUCKET}/${key} --file="${outPath}" --local`, { stdio: "inherit" });
}

// --- 1. File upload: the browser names the multipart part "blob" (common
// for JS-driven uploads), so the real filename only comes from
// gateway_http's FileInfo -- matched by the file's SHA-256.
const uploadRequestId = "req-upload-0001";
const uploadFileName = "고객명단_2026.csv";
const uploadFileBytes = Buffer.from("이름,전화번호\n홍길동,010-0000-0000\n", "utf8");
const uploadFileSha256 = createHash("sha256").update(uploadFileBytes).digest("hex");
const boundary = "----SampleBoundary7MA4YWxk";
const uploadMultipart = Buffer.concat([
  Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="folderId"\r\n\r\nroot\r\n`, "utf8"),
  Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="blob"\r\nContent-Type: text/csv\r\n\r\n`, "utf8"),
  uploadFileBytes,
  Buffer.from(`\r\n--${boundary}--\r\n`, "utf8"),
]);

// --- 2. Non-file request/response pair (e.g. a GenAI prompt), to exercise
// bodyPreview and Content-Encoding decompression.
const promptRequestId = "req-prompt-0001";
const promptBody = JSON.stringify({ prompt: "샘플 테스트 프롬프트입니다.", model: "claude-test", locale: "ko-KR" });
const completionBody = JSON.stringify({ type: "completion", content: "샘플 응답입니다." });

const httpLines = [
  {
    Datetime: iso(5000),
    RequestID: uploadRequestId,
    Email: "user1@example.com",
    SourceIP: "203.0.113.10",
    DestinationIP: "198.51.100.20",
    HTTPHost: "upload.storage.example",
    URL: "https://upload.storage.example/api/v1/files",
    HTTPMethod: "POST",
    HTTPStatusCode: 200,
    Action: "allow",
    PolicyName: "Forensic copy - file uploads",
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
  },
  {
    Datetime: iso(4000),
    RequestID: promptRequestId,
    Email: "user2@example.com",
    SourceIP: "203.0.113.11",
    DestinationIP: "198.51.100.30",
    HTTPHost: "chat.example",
    URL: "https://chat.example/api/completion",
    HTTPMethod: "POST",
    HTTPStatusCode: 200,
    Action: "allow",
    PolicyName: "Forensic copy - GenAI",
  },
  {
    Datetime: iso(3000),
    RequestID: "req-plain-0001",
    Email: "user3@example.com",
    HTTPHost: "example.com",
    URL: "https://example.com/",
    HTTPMethod: "GET",
    HTTPStatusCode: 200,
    Action: "allow",
  },
];

const forensicLines = [
  {
    AccountID: "acct-sample",
    Datetime: iso(5000),
    ForensicCopyID: "fc-upload-0001",
    GatewayRequestID: uploadRequestId,
    Phase: "request",
    TriggeredRuleID: "00000010-forensic-upload-sample",
    Headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
    Payload: uploadMultipart.toString("base64"),
  },
  {
    AccountID: "acct-sample",
    Datetime: iso(4000),
    ForensicCopyID: "fc-prompt-0001",
    GatewayRequestID: promptRequestId,
    Phase: "request",
    TriggeredRuleID: "00000009-forensic-genai-sample",
    Headers: { "content-type": "application/json" },
    Payload: Buffer.from(promptBody, "utf8").toString("base64"),
  },
  {
    AccountID: "acct-sample",
    Datetime: iso(3900),
    ForensicCopyID: "fc-prompt-0002",
    GatewayRequestID: promptRequestId,
    Phase: "response",
    TriggeredRuleID: "00000009-forensic-genai-sample",
    // gzip stands in for the "br" real streamed responses often use.
    Headers: { "content-type": "text/event-stream", "content-encoding": "gzip" },
    Payload: gzipSync(Buffer.from(completionBody, "utf8")).toString("base64"),
  },
];

putObject(`http/sample-${nowMs}.log.gz`, httpLines);
putObject(`forensic/sample-${nowMs}.log.gz`, forensicLines);

console.log("Done.");
console.log(`File lookup:   curl -H "Authorization: Bearer <LOOKUP_TOKEN>" "http://127.0.0.1:8787/forensic/lookup?request_id=${uploadRequestId}"`);
console.log(`Prompt lookup: curl -H "Authorization: Bearer <LOOKUP_TOKEN>" "http://127.0.0.1:8787/forensic/lookup?request_id=${promptRequestId}"`);
console.log(`Expected file sha256: ${uploadFileSha256}`);
