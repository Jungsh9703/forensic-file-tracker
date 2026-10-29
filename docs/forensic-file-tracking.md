# Forensic Copy 기반 파일 전송 추적 — 요구사항 / 단계 계획

> 구성 원칙: 외부 클라우드/도구 없이 **Cloudflare R2 + D1 + Workers만** 사용합니다.

DLP Forensic Copies(`dlp_forensic_copies`)와 Gateway HTTP 로그(`gateway_http`)를
`GatewayRequestID` = `RequestID`로 이어 붙여, **누가 · 언제 · 어디로 · 어떤 파일을**
보냈는지와 그 **원본 파일**까지 확인할 수 있게 만드는 작업입니다. 세 단계로 나눠
순서대로 진행합니다.

## 전체 흐름

```
Logpush ─┬─ dlp_forensic_copies ──▶ R2 forensic/   (Payload = base64 원문)
         └─ gateway_http        ──▶ R2 http/       (RequestID, Email, Host, URL, FileInfo ...)
                                         │
                       ┌─────────────────┘
                       ▼
 [1단계] Worker: 디코딩 → 파일 추출 → 해시 → RequestID 조인 → 파일명 확정
 [2단계] D1(SQL): 정규화된 행으로 적재, 정렬/검색 쿼리
 [3단계] 대시보드: SQL 결과를 화면으로 + 원본 파일 열람
```

---

## 1단계 — 추출 · 디코딩 · 해시로 파일명 조회 (현재 단계)

### 입력
- R2 `forensic/` 아래 Forensic Copy NDJSON(.gz)
- R2 `http/` 아래 Gateway HTTP NDJSON(.gz)

### Forensic Copy에서 뽑을 값
| 필드 | 처리 |
|---|---|
| `Datetime` | epoch ms + ISO 문자열로 정규화 |
| `GatewayRequestID` | 조인 키 |
| `Headers` | 그대로 보존. `content-type`(multipart boundary), `content-encoding` 사용 |
| `Payload` | base64 디코딩 → `Content-Encoding`에 따라 gzip/deflate/br 해제 |
| `Phase` | 파일 업로드 판별에 사용 (`request`만 대상) |

### 파일 업로드 판별 / 추출
1. `Phase = request` 이고
2. `content-type`이 `multipart/form-data` → 파트별로 `filename=`이 있는 파트를 파일로 추출
3. 그 외 바이너리 본문(`application/octet-stream` 등, 텍스트/JSON/form-urlencoded 제외) →
   본문 전체를 파일 1개로 간주
4. 각 파일의 **SHA-256**(필요 시 SHA-1/MD5)을 계산

### HTTP 로그와 매칭 (파일명 확정)
1. `gateway_http`에서 `RequestID = GatewayRequestID`인 레코드를 찾는다
2. 그 레코드의 `FileInfo.files[]`(`file_name`, `file_hash`, `file_size`, `content_type`,
   `direction`, `action`) 중 **`file_hash`가 계산한 해시와 같은 항목**의 `file_name`을
   파일명으로 확정 → `matchedBy = "hash"`
3. 해시 매칭 실패 시 대체 순서: multipart `filename=` → `UploadedFileNames` →
   `matchedBy` 값으로 어느 근거였는지 남긴다
4. 해시 불일치 원인 표시: payload 잘림(truncated), 압축 해제 실패 등

### 결과물 (1단계 완료 기준)
- `GET /forensic/lookup?request_id=<id>[&date=YYYY-MM-DD]` — 위 과정을 수행한 JSON 반환
  (forensic 원본 메타, 추출 파일 목록 + 해시, 매칭된 HTTP 레코드 요약, 확정 파일명/근거)
- `GET /forensic/file?request_id=<id>&sha256=<hash>` — 복원된 원본 파일 다운로드
- 두 엔드포인트 모두 `LOOKUP_TOKEN`(Bearer) 필수 — 실제 파일 내용이 나가는 경로이기 때문
- 로컬 샘플(multipart 업로드 + FileInfo 포함 HTTP 로그)로 해시 매칭이 되는 것을 확인

### 1단계 한계 (2단계에서 해결)
- 저장소 없이 R2를 날짜 단위로 **스캔**해서 찾기 때문에 대량 조회에는 느리다
  (요청당 스캔 오브젝트 수 상한 있음)
- `FileInfo` 하위 키는 Cloudflare 문서에 구조가 없어 서드파티 파서 기준
  (`files[].file_name/file_hash/...`)으로 구현 — 실제 로그 1건으로 재확인 필요

---

## 2단계 — SQL 정리 (D1)

- cron 적재 시 1단계 로직을 그대로 태워 D1에 행 단위로 저장
  - `forensic_files`(copy_id, request_id, ts, file_name, matched_by, sha256, size,
    content_type, r2_key, truncated)
  - `http_requests`(request_id, ts, email, src_ip, dst_ip, host, url, method, action,
    policy, file_info JSON)
- 복원 파일은 R2 `forensic-files/{request_id}/{sha256}`에 저장 (원본 오브젝트는 수정 금지)
- 기본 쿼리: 기간/사용자/목적지/파일명/해시 검색, 시간순 정렬

## 3단계 — 대시보드

- 발신(사용자) · 수신(목적지 Host/URL) · 시간 · 전송 경로 · 파일명 · 해시 · 원본 열람 링크
- Worker가 직접 제공하는 페이지(외부 대시보드 도구 없음) + Cloudflare Access 보호
- 이상 징후 알림(대용량, 특정 확장자, 비업무 도메인 등)은 이 단계 이후 검토
