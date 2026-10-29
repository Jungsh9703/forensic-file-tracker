# Forensic File Tracker

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Jungsh9703/forensic-file-tracker)

Cloudflare Zero Trust Gateway의 **DLP Forensic Copies**와 **Gateway HTTP 로그**를 이어 붙여
누가 · 언제 · 어디로 · 어떤 파일을 보냈는지와 그 **원본 파일**을 확인하는 Worker입니다.
외부 클라우드 없이 **Cloudflare R2 + D1 + Workers**만 사용합니다.

```
Zero Trust Gateway (HTTP 정책: Forensic copy)
      │ Logpush ×2
      ├─ dlp_forensic_copies ──▶ R2  forensic/   (Payload = base64 원문)
      └─ gateway_http        ──▶ R2  http/       (사용자, IP, Host, URL, FileInfo)
                                      │
                                      ▼
                     Worker  forensic-file-tracker
                     [1단계] 디코딩 → 파일 추출 → SHA-256 → RequestID 조인 → 파일명 확정  ✅
                     [2단계] D1 적재 + SQL 조회                                          ⏳
                     [3단계] Worker가 띄우는 대시보드                                    ⏳
```

단계별 요구사항은 [`docs/forensic-file-tracking.md`](docs/forensic-file-tracking.md) 참고.

## 1. Logpush 설정 (Cloudflare 대시보드)

같은 R2 버킷(`sh-logpush-test`)에 Logpush job 두 개를 만듭니다.

| Dataset | R2 경로(prefix) | 필드 |
|---|---|---|
| DLP forensic copies | `forensic/` | 전체 (`Datetime, GatewayRequestID, Headers, Payload, Phase, TriggeredRuleID` 등) |
| Gateway HTTP | `http/` | 최소 `Datetime, RequestID, Email, UserID, SourceIP, DestinationIP, HTTPHost, URL, HTTPMethod, Action, PolicyName, FileInfo, UploadedFileNames` |

prefix는 `wrangler.toml`의 `FORENSIC_LOG_PREFIX` / `HTTP_LOG_PREFIX`와 같아야 합니다.

## 2. 배포

### 방법 A — Deploy to Cloudflare 버튼

맨 위 버튼을 누르면 Cloudflare가 이 저장소를 **내 GitHub 계정으로 복제**한 뒤 Worker를 만들고
배포합니다. 이후 그 복제된 저장소에 push할 때마다 자동으로 다시 배포됩니다.

설정 화면에서:
- **R2 bucket (`LOGS_BUCKET`)**: Logpush job이 쓰고 있는 버킷 이름(`sh-logpush-test`)으로 맞춰주세요.
  다른 이름이면 새 빈 버킷이 만들어져 조회 결과가 비어 나옵니다.
- **`LOOKUP_TOKEN`**: 길고 무작위인 문자열 (예: `openssl rand -hex 32`). 조회할 때 이 값을 씁니다.
- 나머지 값(`HTTP_LOG_PREFIX` 등)은 기본값 그대로 두면 됩니다.

### 방법 B — 로컬에서 wrangler

```bash
npm install
npx wrangler login
npx wrangler secret put LOOKUP_TOKEN   # 길고 무작위인 문자열. 없으면 조회 API가 503
npm run deploy
```

## 3. 사용

모든 요청에 `Authorization: Bearer <LOOKUP_TOKEN>` 헤더가 필요합니다.

- `GET /forensic/lookup?request_id=<GatewayRequestID>[&date=YYYY-MM-DD]`
  - Forensic copy의 `Datetime`, `GatewayRequestID`, `Headers`, 디코딩된 `Payload`
  - 업로드 파일 목록: 파일명, `matchedBy`(`hash` → `multipart` → `uploaded_file_names` 순),
    sha256, 크기, 잘림 여부, 다운로드 경로
  - 매칭된 HTTP 요약: Email, SourceIP, DestinationIP, Host, URL, Method, Action, Policy
- `GET /forensic/file?request_id=<id>&sha256=<hex>[&date=YYYY-MM-DD]` — 복원된 원본 파일 다운로드
  (항상 `application/octet-stream` 첨부파일로 내려줌)

`date`를 생략하면 어제·오늘(UTC)을 스캔합니다. 프리픽스당 최대 `MAX_LOOKUP_OBJECTS`개 오브젝트만
읽으며, 응답의 `scanned.capped`가 `true`면 범위를 `date`로 좁혀 다시 조회하세요.

## 로컬 테스트

```bash
npx wrangler dev --var LOOKUP_TOKEN:local-test-token
```

다른 터미널에서:

```bash
npm run seed:local
curl -H "Authorization: Bearer local-test-token" "http://127.0.0.1:8787/forensic/lookup?request_id=req-upload-0001"
```

`files[0].fileName`이 `고객명단_2026.csv`, `matchedBy`가 `hash`면 정상입니다 (multipart 파트 이름은
`blob`이라, 파일명은 해시 매칭으로만 알 수 있게 만든 샘플).

## 주의

- **민감 데이터**: Forensic copy는 메타데이터가 아니라 실제 요청 본문/파일입니다. `LOOKUP_TOKEN`을
  공유 범위에 맞게 관리하고, 3단계 대시보드는 Cloudflare Access로 보호할 예정입니다.
- **암호화 아님**: `Payload`는 base64(+`Content-Encoding`에 따른 gzip/deflate/br)일 뿐이라
  복호화 키가 필요 없습니다 (`src/decode.ts`).
- **`FileInfo` 구조**: Cloudflare 문서엔 "object"로만 나와 있어 `files[].file_name/file_hash/...`
  구조(서드파티 파서 기준)로 구현했습니다. 실제 업로드 로그 1건으로 확인이 필요합니다.
