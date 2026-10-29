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
                     [2단계] cron(1분) → D1 적재 + /api/transfers 조회                   ✅
                     [3단계] Worker가 띄우는 대시보드                                    ⏳
```

### D1 구조 (2단계)

두 Logpush 데이터는 도착 순서가 보장되지 않아 **각각 그대로 저장하고, 조회할 때 합칩니다** —
HTTP 로그가 늦게 와도 다음 조회부터 자동으로 채워집니다. 테이블은 Worker가 처음 실행될 때
직접 만듭니다(`src/schema.ts`, 별도 마이그레이션 불필요).

| 테이블/뷰 | 내용 |
|---|---|
| `http_requests` | `gateway_http` 중 파일 업로드 가능성이 있는 요청만 (POST/PUT/PATCH 또는 파일 필드가 있는 것) — Email, DeviceName, Host, ApplicationNames, FileInfo 등 |
| `forensic_files` | Forensic copy에서 추출한 파일 1개당 1행 — 시간, RequestID, 크기, SHA-256/SHA-1/MD5. 파일 원본은 R2 `files/`에 저장 |
| `ingested_objects` | 처리 완료한 R2 오브젝트 (중복 처리 방지) |
| **`file_transfers`** (뷰) | 위 두 테이블 조인: **time, email, device_name, host, application_name, file_name** + matched_by, sha256, url 등 |

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

### 파일 전송 조회 (D1, 2단계)

- `GET /api/transfers` — 최신순 목록. 필터(모두 선택, 텍스트는 대소문자 무시 "포함" 검색):
  `from` / `to` (`YYYY-MM-DD` 또는 ISO 시각, 날짜만 주면 그날 하루 포함), `email`, `device`,
  `host`, `app`, `file`, `limit`(기본 100, 최대 1000), `offset`
  ```bash
  curl -H "Authorization: Bearer $TOKEN" "https://<worker>.workers.dev/api/transfers?from=2026-10-29&email=user1"
  ```
  각 항목: `time, email, deviceName, host, applicationName, fileName` + `matchedBy`, `size`,
  `sha256`, `requestId`, `url`, `method`, `action`, `policyName`, `sourceIP`, `destinationIP`,
  `httpMatched`(HTTP 로그 도착 여부), `downloadPath`
- `GET /api/files/<request_id>/<sha256>` — 원본 파일 다운로드
- `GET /api/status` — 데이터가 쌓이고 있는지: 행 수, 마지막 수신 시각, 최근 처리한 R2 오브젝트
- `POST /api/ingest` — cron을 기다리지 않고 바로 적재

SQL로 직접 보려면 Cloudflare 대시보드 → **Storage & Databases → D1 → forensic-file-tracker →
Console**에서:

```sql
SELECT time, email, device_name, host, application_name, file_name
FROM file_transfers ORDER BY ts DESC LIMIT 50;
```

### R2 직접 조회 (1단계, 요청 1건 디버깅용)

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
curl -X POST -H "Authorization: Bearer local-test-token" http://127.0.0.1:8787/api/ingest
curl -H "Authorization: Bearer local-test-token" http://127.0.0.1:8787/api/transfers
```

`fileName`이 `고객명단_2026.csv`, `matchedBy`가 `hash`, `deviceName`이 `LAPTOP-SH01`이면
정상입니다 (multipart 파트 이름은 `blob`이라, 파일명은 해시 매칭으로만 알 수 있게 만든 샘플).
`wrangler dev`를 `--persist-to <dir>`로 띄웠다면 시드도 `WRANGLER_PERSIST_TO=<dir> npm run seed:local`.

## 주의

- **민감 데이터**: Forensic copy는 메타데이터가 아니라 실제 요청 본문/파일입니다. `LOOKUP_TOKEN`을
  공유 범위에 맞게 관리하고, 3단계 대시보드는 Cloudflare Access로 보호할 예정입니다.
- **암호화 아님**: `Payload`는 base64(+`Content-Encoding`에 따른 gzip/deflate/br)일 뿐이라
  복호화 키가 필요 없습니다 (`src/decode.ts`).
- **`FileInfo` 구조**: Cloudflare 문서엔 "object"로만 나와 있어 `files[].file_name/file_hash/...`
  구조(서드파티 파서 기준)로 구현했습니다. 실제 업로드 로그 1건으로 확인이 필요합니다.
