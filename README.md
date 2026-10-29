# Forensic File Tracker (gateway-log-pipeline)

[`Jungsh9703/log_monitor`](https://github.com/Jungsh9703/log_monitor)의 `gateway-log-pipeline`을
독립 저장소로 옮긴 것입니다. Worker 이름(`gateway-log-pipeline`)은 그대로라, 여기서 배포하면
기존에 배포된 같은 Worker를 갱신합니다. Forensic Copy 파일 추적 작업(1~3단계)은 이 저장소에서
진행합니다 — [`docs/forensic-file-tracking.md`](docs/forensic-file-tracking.md).

배포는 이 폴더에서 `npx wrangler login` → `npx wrangler secret put LOOKUP_TOKEN` → `npm run deploy`.


Zero Trust Gateway HTTP 로그 **전체**(필터링 없음)를 R2에서 읽어 Loki로 전송하는 Cloudflare
Worker입니다. 지금까지 배포/테스트해온 것도
전부 이 폴더 기준입니다.

```
Zero Trust Gateway HTTP 트래픽 (전체)
        │
        ▼
Logpush job (dataset: gateway_http) ─────────▶ R2 bucket (raw gzip NDJSON)
                                                        │
                                          Worker cron (1분, 커서로 이어서 처리)
                                          1) gunzip + NDJSON 파싱
                                          2) 필터링 없이 모든 라인을 정규화
                                          3) 정규화된 레코드(+원본 전체) → Loki push (청크 분할)
                                                        │
                                                        ▼
                                   Loki (Azure Ubuntu VM, storage_config.azure)
                                   → 청크/인덱스는 Azure Blob Storage에 저장
                                                        │
                                                        ▼
                                              Grafana Dashboard
```

Loki + Grafana를 실제로 띄우는 Azure VM 스택은 [`log_monitor/loki-grafana-azure-vm`](https://github.com/Jungsh9703/log_monitor/tree/main/loki-grafana-azure-vm)
에 있습니다.

## 왜 Workers KV 대신 Durable Object인가

커서 상태(어떤 R2 오브젝트를 어디까지 처리했는지)를 Workers KV에 저장하면, KV는 **최종적
일관성**(eventually consistent) 모델이라 한 번 쓴 값이 전 세계 엣지에 전파되는 데 최대 60초
정도 걸릴 수 있습니다. cron이 5분 간격이면 문제가 안 되지만, **1분 간격**으로 줄이면 직전 실행이
KV에 쓴 커서를 다음 실행이 아직 전파 안 된 오래된 값으로 읽어서 이미 처리한 오브젝트를 중복
처리하거나 커서가 꼬일 위험이 생깁니다.

Durable Object(`src/cursor_do.ts`의 `IngestCursor`)는 전역에 단 하나의 인스턴스만 존재하고
모든 읽기/쓰기가 그 인스턴스를 강한 일관성으로 통과하기 때문에 이 문제가 없습니다. Cloudflare
대시보드에서는 KV/R2/D1처럼 "Storage & Databases"의 별도 상품이 아니라 **Compute → Workers &
Pages**에 속한 Worker 코드의 일부로 배포됩니다 — `wrangler.toml`의 `durable_objects.bindings` +
`migrations`가 그 역할을 하고, 별도로 리소스를 만들 필요가 없습니다. SQLite 저장 백엔드를 쓰는
Durable Object는 Workers **Free 플랜**에서도 동작합니다(예전 저장 백엔드는 유료 플랜 전용이었지만,
현재는 SQLite 백엔드가 기본이자 무료 플랜 지원 대상입니다 — 배포 시점의 Cloudflare 요금제 페이지로
한 번 더 확인하는 걸 권장합니다).

## 볼륨/비용 주의

전체 로그를 다 보내므로 트래픽이 많은 계정이면 R2 저장량, Loki 처리량, Azure Blob 저장량이
빠르게 늘어날 수 있습니다.

- 실제 병목은 보통 `MAX_LINES_PER_OBJECT_RUN`이 아니라 **`MAX_OBJECTS_PER_RUN`**입니다 —
  Logpush는 큰 오브젝트 몇 개보다 작은 오브젝트를 자주 쓰는 경향이 있어서, 줄 수 한도는
  넉넉해도 오브젝트 개수 한도에 먼저 걸려 처리가 밀릴 수 있습니다. `runIngestion`은 대부분
  R2/Durable Object 호출을 기다리는 I/O 시간이라 Workers **CPU 시간** 예산에는 거의 안 잡히고
  (CPU 시간은 실제 JS 연산만 카운트), 늘려도 주로 **wall time**만 늘어납니다. 값을 바꾼 뒤엔
  Worker의 **Metrics** 탭에서 **"Exceeded CPU Time"**이 0으로 유지되는지 보면서 Free 플랜
  기준 안전한지 확인하세요. 트래픽이 분당 200~300줄 정도라면 `MAX_OBJECTS_PER_RUN=30` 정도가
  기본값입니다 — 그래도 밀리면 더 올리고, 반대로 트래픽이 적다면 낮춰도 됩니다.
- Loki 쪽 리텐션(`limits_config.retention_period` 등)을 설정해 오래된 로그를 자동 삭제하는
  것도 고려하세요 — `log_monitor/loki-grafana-azure-vm/loki-config.yml`에는 기본값이 없으니 필요하면
  추가하세요.
- 정말 전체가 필요한 게 아니라 특정 조건(예: 특정 정책, 특정 호스트)만 필요하다면 Logpush job
  자체에 필터를 걸어 R2에 도착하는 양부터 줄이는 것도 방법입니다.

## 로컬 동작 확인 (Loki 없이 파싱만)

```bash
npm install
npm run dev
```

다른 터미널에서:

```bash
npm run seed:local
curl -X POST http://127.0.0.1:8787/run
```

`/run` 응답의 `recordsShipped`가 샘플 줄 수(10)와 같으면 파싱이 정상입니다 — 필터링이 없으므로
모든 줄이 카운트됩니다. `LOKI_URL`이 아직 가짜 값이라 마지막 `pushToLoki` 호출은 실패하는 게
정상입니다.

Loki까지 포함해 로컬로 가볍게 검증하려면 (filesystem 백엔드, Azure 없이):

```bash
docker compose up -d
```

- Grafana: http://localhost:3000 (익명 Admin 접속 허용)
- 좌측 Dashboards → **Gateway HTTP Logs (All Traffic)**

## 프로덕션 배포

### 1. R2 버킷 생성

```bash
wrangler r2 bucket create gateway-log-raw
```

커서 저장용 Durable Object는 별도로 만들 게 없습니다 — `npm run deploy`가 `wrangler.toml`의
마이그레이션을 보고 알아서 프로비저닝합니다.

### 2. Logpush job 생성

Cloudflare 대시보드 → 계정 홈 → **Analytics & Logs → Logpush** → Add a Logpush job:

- Dataset: `gateway_http`
- Destination: 위에서 만든 `gateway-log-raw` R2 버킷, **prefix를 `http/`로 지정**
  (destination 문자열 끝에 `/http`를 붙이는 형식 — 대시보드의 R2 설정 화면에 경로 입력란이
  있습니다). `wrangler.toml`의 `HTTP_LOG_PREFIX`와 정확히 일치해야 Worker가 이 오브젝트들을
  찾습니다.
- 필터: 전체를 보고 싶은 목적이므로 걸지 않습니다. 필드는 **Select All**을 권장합니다 —
  `normalize.ts`가 참조하는 필드(`PolicyName`, `CategoryNames` 등)가 빠지지 않도록.

### 2-1. (선택, 민감) DLP Forensic Copies job 추가

같은 R2 버킷에 **prefix `forensic/`**로 두 번째 Logpush job을 추가하면, DLP 정책에 실제로
매치된 **요청/응답 본문 그 자체**를 받아볼 수 있습니다:

- Dataset: **DLP forensic copies**
- Destination: 같은 `gateway-log-raw` 버킷, prefix `forensic/` (`FORENSIC_LOG_PREFIX`와 일치)
- 필드: `AccountID, Datetime, ForensicCopyID, GatewayRequestID, Headers, Payload, Phase,
  TriggeredRuleID`이 전부입니다 (다른 옵션 없음).

**이 데이터는 암호화되어 있지 않습니다** — 처음엔 "Payload가 암호화된 것 아닌가" 의심했지만,
실제 샘플 두 건을 직접 디코딩해보니 `Payload`는 그냥 **base64**였습니다. `request` phase
샘플은 base64 디코딩만으로 바로 읽을 수 있는 평문 JSON(실제 claude.ai 요청 본문)이 나왔고,
`response` phase 샘플이 무작위로 보였던 건 암호화가 아니라 그 레코드의 `Headers`에 있는
`content-encoding: br`(Brotli 압축) 때문이었습니다. 즉 필요한 건 개인키 복호화가 아니라
**base64 디코딩 + `Content-Encoding`에 따른 압축 해제**뿐이고, `src/forensic.ts`가 이걸
처리합니다 (`node:zlib`의 gunzip/inflate/brotliDecompress — Worker가 `nodejs_compat`
플래그로 이 모듈을 씁니다, `crypto.ts`의 HPKE 로직과는 무관). **새 시크릿이 필요 없습니다.**

**민감도 주의**: 이건 메타데이터가 아니라 실제 대화/문서 내용입니다 — 개인 테스트 용도로만
켜두고, `gateway-forensic-copies` Grafana 대시보드나 `job="gateway_forensic_logs"` Loki
스트림에 대한 접근 범위를 넓히기 전에 다시 한 번 생각해보세요.

### 2-2. Forensic Copy 파일 조회 (1단계)

`GatewayRequestID` 하나로 forensic copy와 `gateway_http` 레코드를 R2에서 직접 찾아
Payload를 디코딩하고, 업로드된 파일을 추출해 **SHA-256 → `FileInfo.files[].file_hash`**
매칭으로 파일명을 확정합니다. 단계 계획 전체는
[`docs/forensic-file-tracking.md`](docs/forensic-file-tracking.md) 참고.

```bash
wrangler secret put LOOKUP_TOKEN   # 필수 -- 없으면 두 엔드포인트 모두 503
```

- `GET /forensic/lookup?request_id=<id>[&date=YYYY-MM-DD]` — 디코딩 결과, 추출 파일
  목록(파일명, `matchedBy`: hash/multipart/uploaded_file_names, sha256, 크기, 잘림 여부),
  매칭된 HTTP 요약(Email, SourceIP, DestinationIP, Host, URL, Method)
- `GET /forensic/file?request_id=<id>&sha256=<hex>[&date=...]` — 복원된 원본 파일 다운로드
- 둘 다 `Authorization: Bearer <LOOKUP_TOKEN>` 헤더 필요. `date`를 안 주면 어제·오늘(UTC)을
  스캔하고, 프리픽스당 최대 `MAX_LOOKUP_OBJECTS`개 오브젝트까지만 읽습니다 (`scanned.capped`로 확인)

로컬: `npx wrangler dev --var LOOKUP_TOKEN:local-test-token` → `npm run seed:local` →
`curl -H "Authorization: Bearer local-test-token" "http://127.0.0.1:8787/forensic/lookup?request_id=req-upload-0001"`

### 3. Azure VM에 Loki + Grafana 배포

아직 안 했다면 [`log_monitor/loki-grafana-azure-vm/README.md`](https://github.com/Jungsh9703/log_monitor/blob/main/loki-grafana-azure-vm/README.md)를
먼저 진행해서 `http://<VM_PUBLIC_IP>.nip.io:3100/loki/api/v1/push`와 nginx Basic Auth
계정을 확보하세요. **`.nip.io`를 꼭 붙이세요** — Cloudflare Worker의 `fetch()`는 URL이 IP
주소 그대로면 Cloudflare 엣지가 가로채서 자체 "error code: 1003"을 반환하고 VM까지 아예
도달하지 못합니다. nip.io는 IP를 그대로 도메인처럼 쓰게 해주는 무료 퍼블릭 DNS라 이 문제를
우회합니다 (VM의 nginx는 Host 헤더를 안 보므로 별도 설정 불필요).

### 4. wrangler.toml 값 + 시크릿 설정

`wrangler.toml`의 `LOKI_URL`/`LOKI_USERNAME`(둘 다 평문 변수)을 3단계에서 만든 주소/계정으로
바꾸고, 비밀번호만 시크릿으로 등록합니다:

```bash
wrangler secret put LOKI_API_KEY      # nginx Basic Auth 계정의 비밀번호
wrangler secret put RUN_TOKEN         # 선택
```

(도메인을 마련해서 Cloudflare Tunnel + Access로 바꾸는 경우에만 대신 `CF_ACCESS_CLIENT_ID`/
`CF_ACCESS_CLIENT_SECRET`을 씁니다 — `src/loki.ts`가 둘 다 지원합니다.)

**선택 아님, 사실상 필수: Gateway 정책 이름 표시** — 처음엔 `PolicyName`이 항상 채워져
있을 거라 가정했는데, 실제 트래픽으로 확인해보니 **정책/트래픽 유형에 따라 이 필드 자체가
빠져 있는 경우가 있습니다** — 예를 들어 "Do Not Inspect" 같은 시스템 bypass 정책은
`HTTPMethod`/`URL`/`RequestID`와 함께 `PolicyName`도 로그에 안 실립니다 (Cloudflare 쪽에서
그렇게 보내는 것이지 저희 파싱 문제가 아닙니다). 이런 경우 `policy_name`이 UUID로 보이는 걸
막으려면 Cloudflare API로 ID→이름을 직접 조회하는 이 fallback이 필요합니다.

1. Cloudflare 대시보드 → 우측 상단 프로필 → **My Profile → API Tokens → Create Token** →
   Custom token → Permissions: **Account → Zero Trust → Read** (계정에 따라 세분화된
   "Gateway" 전용 권한이 안 보이면 이 `Zero Trust` 항목이 맞습니다)
2. 계정 ID는 대시보드 우측 사이드바 또는 `wrangler whoami`로 확인
3. `wrangler.toml`의 `[vars]`에 `CF_ACCOUNT_ID = "..."` 채우고:
   ```bash
   wrangler secret put CF_API_TOKEN
   ```

30분 캐시(Durable Object에 저장)로 API를 매 cron마다 호출하지 않도록 했습니다.

**선택: DLP 프로필/엔트리 이름 표시** — `Upload/DownloadMatchedDlpProfiles`/`...ProfileEntries`는
로그에 이름 필드 자체가 없어서(Cloudflare Zero Trust UI에서는 "카드번호_DLP" 같은 이름으로
보이는 그 값) 항상 UUID로만 옵니다. 같은 방식으로 `/accounts/{id}/dlp/profiles` API를 조회해서
채워줍니다. 위 `CF_ACCOUNT_ID`/`CF_API_TOKEN`을 이미 설정했다면 추가 설정 없이 같이 동작합니다 — 토큰
권한이 부족하면(DLP 프로필 조회가 별도 권한일 수 있음) 이 부분만 조용히 실패하고 원본 UUID로
표시되니, 이름이 안 뜨면 토큰에 **Account → DLP → Read** 권한을 추가해보세요.

이 API의 개별 엔트리(프로필 안의 세부 탐지 규칙) 이름 필드 구조는 Cloudflare 문서에서 완전한
예시를 못 찾아서 추정으로 짜놨습니다(`src/dlp_profile_names.ts`) — 프로필 이름은 뜨는데 엔트리
이름이 안 뜨면 알려주시면 실제 API 응답 보고 고치겠습니다.

**참고: GenAI prompt / DLP 매치 내용 복호화 기능은 현재 데이터가 안 옵니다** — Gateway HTTP
정책의 "Capture generative AI prompt content in logs"나 DLP 매치 시 Zero Trust 대시보드의
"Decrypt payload log" 버튼으로 볼 수 있는 암호화된 내용을, 이 Worker가 대신 자동으로 복호화해
Grafana에서 보여주는 기능(`src/dlp.ts`, `src/crypto.ts`)을 만들어뒀습니다 — 로직 자체는 자체
생성한 키 페어로 실제 왕복 테스트까지 마쳤습니다. 다만 R2에 실제로 쌓이는 `gateway_http`
Logpush 오브젝트를 열어서 전체 필드(약 60개, "Select All" 기준)를 확인해보니, GenAI
prompt/DLP 매치 컨텍스트에 해당하는 필드가 **하나도 없었습니다** — Zero Trust 대시보드의 로그
뷰어는 Logpush와는 별도의 실시간 조회 API를 쓰는 것으로 보이고, 그쪽에서만 이 내용이 노출되는
것 같습니다. 즉 현재 구조(Logpush → R2 → Worker)로는 이 기능이 실제로 쓰일 데이터가 없을 수
있습니다. Logpush job 생성 화면의 **Advanced Options**에 추가 필드 옵션이 있는지 한 번
확인해봐 주시겠어요 — 있으면 여기서 다시 살펴보겠습니다. 설정 자체(`DLP_PRIVATE_KEY` 시크릿)는
해가 되지 않으니 그대로 남겨뒀습니다.

### 5. 배포

```bash
npm run deploy
```

`wrangler tail`로 `recordsShipped`가 늘어나는지, `pushToLoki` 관련 에러(401/403, 요청 크기
초과 등)가 없는지 확인하세요.

## 필드 검증 (중요)

`src/normalize.ts`의 필드명은 **PascalCase**입니다 (`Action`, `PolicyID`, `PolicyName`,
`HTTPHost`, `HTTPMethod`, `HTTPStatusCode`, `Email`, `UserID`, `RequestID`, `IsIsolated`,
`SourceIPCountryCode`, `DestinationIPCountryCode`, `CategoryIDs`, `CategoryNames`,
`Upload/DownloadMatchedDlpProfiles(Entries)` 등) — **Logpush가 실제로 R2에 쓰는 오브젝트를
직접 다운로드해서 확인한 값**입니다.

**주의**: Zero Trust 대시보드의 **Logs → HTTP request logs** 뷰어에서 로그를 펼쳐 **JSON**
탭으로 보이는 필드는 snake_case(`action_name`, `http_host` 등)인데, 이건 Logpush와는 **별개의
실시간 조회 API**의 스키마입니다 — R2/Loki에 실제로 들어오는 데이터와 다르니 필드명 참고용으로
쓰지 마세요. 필드명을 다시 확인해야 한다면, Cloudflare 대시보드의 R2 버킷에서 오브젝트를 직접
다운로드해서(`.gz` 압축 해제) 열어보거나, Grafana Explore에서
`{job="gateway_http_logs"} | json`으로 확인하세요 (로그 라인에 `raw`로 원본 전체가 같이
실려 있습니다).
