# Hunter 개발 에이전트 지침

이 문서는 저장소 전체에서 작업하는 개발 에이전트와 기여자를 위한 지침입니다.
사용자의 현재 요청과 이미 합의한 작업 범위를 우선하고, 기존 변경을 보존하며 구현·검증·문서화를 끝까지 수행합니다.
## 1. 작업 시작과 협업

- 먼저 `git status --short`로 기존 변경을 확인하고 자신의 작업 범위를 정합니다.
- 버전은 `VERSION`, 도구 버전은 `go.mod`와 npm 잠금 파일을 기준으로 확인합니다. API 계약은 `internal/app/openapi.json`과 실제 라우트·권한 검사에서 확인합니다.
- `CONTRACT.md`는 초기 구현 기록입니다. 오래된 버전·계획을 최신 코드보다 우선하지 않습니다.
- 같은 파일의 담당 범위를 조율하고 사용자의 기존 변경·다른 에이전트 작업을 되돌리거나 무관한 형식 변경을 섞지 않습니다.
- 실제 수행하지 않은 테스트·배포·진단 결과를 완료로 보고하지 않습니다.
## 2. 저장소 구조

| 경로 | 역할 |
| --- | --- |
| `cmd/hunter/main.go` | 환경변수, 서버·워커 실행, 버전 주입 |
| `internal/app` | Go HTTP API, 인증·권한, 설정, 자산·발견 건·진단·연동 |
| `internal/app/campaigns.go` | 캠페인 원자적 시작·현재 부모 권한·불변 관측 비교 |
| `internal/app/finding_ops*.go`, `finding_bulk.go` | 조치함·SLA·위협 정보·댓글·현재 권한의 원자적 일괄 변경 |
| `internal/app/finding_evidence.go`, `notifications*.go` | 기존 증거 배치 복구, 암호화 알림 큐·규칙·SMTP/HTTP 전송 |
| `internal/app/notification_automation*.go`, `notification_operations*.go` | 동적 수신·묶음·업무 확인·보존, 전달 결과·대체 채널·보호 |
| `internal/app/automation_workflows*.go`, `automation.go` | 서명 변경 규칙·ITSM 동기화·제어 서버 자동화 루프 |
| `internal/app/sbom.go`, `operations.go` | SBOM 구성·비교·영향 범위와 관리자 운영 점검 |
| `internal/app/agents.go` | 에이전트 실행 API, 조회·생성·중지·SSE |
| `internal/app/agents_runner.go` | 원본 코어와 Hunter 실행 수명·한도 연결 |
| `internal/app/agents_llm.go`, `agent_models*.go` | 네이티브 모델·대체 연결·응답 커밋과 도구 조각 조립 |
| `internal/app/agent_search*.go`, `agent_memory*.go`, `agent_telemetry*.go` | 선택 검색·로컬 원본 메모리·암호화 관측 큐 |
| `internal/app/agent_execution*.go`, `agents_control.go` | 고정 mTLS 격리 프로브·체크포인트 제어·입력·도구 영수증 |
| `internal/app/graphql*.go`, `agent_reports*.go`, `report_assets` | 현재 권한의 조회 GraphQL·오프라인 한글 보고서·폰트 고지 |
| `internal/app/auth_oidc*.go`, `tracking*.go`, `web/src/auth-flow.ts`, `tracking*` | 한 번의 OIDC 자동 진입·로컬 복구와 관리자 격리 추적 |
| `internal/app/agents_tools.go` | 여덟 Hunter 도구의 권한·범위·저장 처리 |
| `internal/app/agents_redaction.go` | 모델·이벤트의 비밀정보 마스킹 |
| `internal/pentagicore` | 원본 코어 어댑터, 모델·도구 연결, 호환 SQL 저장소 |
| `third_party/pentagi` | 고정 원본 코어, 라이선스, 출처·파일 해시 |
| `web/src` | React·TypeScript·Mantine 화면과 한국어 문구 |
| `web/src/agents.tsx`, `agent-controls.tsx`, `agent-platform*.tsx` | 에이전트 목록·상세·명시 재개·추가 입력·관리자 선택 연동 |
| `web/src/triage.tsx`, `software.tsx`, `campaigns.tsx`, `operations.tsx` | 조치·SBOM·캠페인·운영과 현재 권한 적용 |
| `web/src/workflow-navigation.ts`, `resource-form-state.ts`, `finding-bulk*.tsx`, `list-export.ts` | 탭별 조건·초안 복사·편집 기준·일괄 변경·CSV와 주소 복사 |
| `web/src/agent-events.ts`, `use-agent-run.ts` | SSE 이벤트 병합·재연결 |
| `web/src/list-view.ts`, `use-list-view.tsx` | 검색·정렬·페이지 처리, URL 목록 상태와 공통 컨트롤 |
| `web/src/list-tools.tsx`, `saved-list-views.ts` | 사용자·메뉴별 목록 보기, 결과 수·조건 해제·표 표시 설정 |
| `web/src/form-feedback.tsx`, `form-state.ts`, `notification-*.ts`, `notifications*.tsx` | 입력 보호·알림센터·미리보기·전달 이력 |
| `web/src/automation*.tsx`, `notification-automation.tsx`, `notification-operations.tsx`, `workflow-automation.tsx`, `personal-inbox.tsx` | 관리자 자동화와 현재 수신자 업무 알림 |
| `web/src/accessibility.ts`, `accessibility.css` | 본문 이동, 모바일 메뉴와 빠른 이동의 키보드 초점 |
| `web/src/navigation.ts`, `quick-navigation.tsx` | 권한을 적용한 빠른 이동, 사용자별 즐겨찾기·최근 방문 |
| `web/tests` | 프런트엔드 권한·이벤트 회귀 테스트 |
| `internal/webassets/dist` | Go 실행 파일에 포함하는 프런트엔드 빌드 결과 |
| `docs` | GitHub Pages, 화면 캡처, 사용자·관리자 가이드 |
| `scripts` | 릴리즈·문서 생성·원본 검증·라이선스 수집 |
| `.github/workflows` | CI, 단일 이미지 릴리즈, GitHub Pages 배포 |
## 3. 유지해야 하는 배포 조건

- 서비스 이름은 `hunter`이며 Go 서버가 8080 포트에서 API와 React 자산을 제공합니다.
- 공개 런타임 환경변수는 아래 네 개만 사용합니다.
  - `POSTGRES_DSN`
  - `BOOTSTRAP_ADMIN`
  - `BOOTSTRAP_ADMIN_PASSWORD`
  - `ENCRYPTION_KEY`
- OIDC, AI, 역할·정책, 내부 CA, 에이전트와 알림 채널·규칙은 관리자 화면과 DB 설정으로 관리합니다.
- 편의상 새 런타임 환경변수나 별도 필수 서비스를 추가하지 않습니다.
- PostgreSQL은 사내 별도 서비스입니다. 에이전트 코어도 같은 DSN의 일반 PostgreSQL을 사용합니다.
- 기존 DB의 bootstrap 계정·비밀번호를 덮어쓰지 않고, DB에 맞지 않는 암호화 키로 시작하지 않습니다.
- UI·폰트·아이콘·파비콘은 이미지에 포함하고 외부 CDN에 의존하지 않습니다.
- 컨테이너는 UID 10001, 읽기 전용 파일 시스템, 권한 제거 조건에서 실행 가능해야 합니다.
- Docker 소켓, 호스트 셸, 원본 PentAGI 실행 이미지나 외부 검색을 자동 활성화하지 않습니다.
- 망별 워커는 같은 이미지의 `--worker-only --worker-id <워커ID>`와 같은 네 환경변수를 사용합니다.
- 워커의 활성화와 서비스 망의 정확한 일치는 관리자 설정으로 통제합니다.
## 4. 인증·권한과 데이터 경계

- 관리자·개인화 기능을 분리하고 개인 키는 명시적 키 권한과 현재 역할 권한의 교집합을 적용합니다.
- 관리자 소유 키라는 이유로 키에 없는 권한을 부여하지 않습니다.
- 키 회전·폐기·만료, 계정 비활성화와 역할·팀 변경을 이후 요청·예약·에이전트 실행에 반영합니다.
- 목록뿐 아니라 상세·SSE·집계·그래프·보고서·내보내기에서도 서비스·팀 접근 범위를 검사합니다.
- 팀장 역할에 다른 팀 열람·승인 권한을 주지 않습니다. 에이전트 읽기에는 `agents:read`, `services:read`, `findings:read`, `scans:read`가 모두 필요합니다.
- 에이전트 생성에는 추가로 `agents:write`, `ai:use`가 필요합니다.
- 프런트엔드 메뉴 숨김을 서버 권한 검사의 대체 수단으로 취급하지 않습니다.
- 쿠키 인증 변경 요청은 기존 Origin 검사와 `X-Hunter-CSRF` 규칙을 유지합니다.
- 비밀값을 설정 조회·감사·오류·스크린샷에 노출하지 않고 기존 암호화·마스킹 경로를 사용합니다.
- 캠페인은 모든 현재 부모 서비스 접근을 검사하며 비교에는 findings:read도 필요합니다. 대상 복사는 새 초안만 만듭니다.
- 일괄 변경은 최대 100개·현재 역할/키/부모 권한·각 updated_at을 검사하고 한 항목 충돌도 전체 롤백합니다.
- 일반 자원 수정은 원래 조회한 expected_updated_at을 전달하고 409에서 입력을 유지합니다. 설정·워커에 같은 계약을 가정하지 않습니다.
- 조치함·SBOM·캠페인 집계에서 기존 잘린 일반 목록을 전체 데이터로 합산하지 않습니다.
## 5. PentAGI 원본 보존

- 기준 커밋은 `ea665308baaff015b226f308438a68d929d0f29b`입니다.
- `third_party/pentagi/UPSTREAM.json`의 `original_files_sha256`에 원본 312파일을 기록합니다.
- 원본 파일은 자동 포맷·일괄 치환 없이 바이트 보존하고 연결 변경은 `internal/pentagicore`와 Hunter bridge에서 해결합니다.
- bridge 경로는 `third_party/pentagi/backend/pkg/providers/hunter_bridge.go`입니다.
- `replace pentagi => ./third_party/pentagi/backend`의 로컬 모듈 연결을 유지합니다.
- 원본 계획·위임·수행·재시도·성찰·요약 경로를 모조 실행기로 바꾸고 통합 완료라고 설명하지 않습니다.
- 원본 Docker·Graphiti·벡터 확장·클라우드·텔레메트리 스택은 자동 초기화하지 않습니다. 관리자가 켠 Hunter 선택 어댑터는 별도 경로이며 원본 312파일을 변경하지 않습니다.
- 코어 호환 스키마의 대화 기록에는 별도 필드 암호화가 없습니다. 일반 UI에 노출하지 않습니다.
- 사용자 화면 이벤트·메모리·발견 증거의 암호화와 코어 DB·백업의 접근 통제를 구분합니다.
- 원본 업데이트가 작업 범위에 포함되면 출처·파일 해시·라이선스·어댑터 호환성을 함께 갱신합니다.
- 변경 전후 `node scripts/verify-pentagi.mjs`로 원본 해시를 검사합니다.
## 6. AI와 실제 실행 통제

- AI API는 스트리밍을 기본으로 하고 UTF-8·SSE 경계에서 나뉜 응답과 도구 인자를 복원합니다.
- 최대 262,144 토큰 설정을 다루되 실제 공급자의 컨텍스트·출력 한도를 함께 적용합니다.
- 입력 바이트 기반 예산 검사를 정확한 모델 토큰 계산으로 설명하지 않습니다.
- 에이전트는 기본 비활성화이며 진단 요청 도구도 별도 허용이 필요합니다.
- 실제 행위는 `service_context`, `list_findings`, `request_scan`, `scan_result`에 한정된 조회·진단과,
  `record_candidate`, `remember`, `recall`과 비신뢰 참고 자료를 반환하는 `search_reference`로 연결합니다.
- 원본 역할 체인 호출별 반복 24회와 실행 전체 모델 호출 60회·Hunter 도구 호출 40회·활성 시간 15분 한도를 구분합니다. 명시 재개 시 반복 한도는 새 체인 호출에 적용하고 전체 호출·활성 시간은 누적합니다.
- 원본 역할 위임은 Hunter 도구 수에 포함하지 않습니다. SSE 끊김은 서버 취소가 아니며 ID 기반 재연결·중복 제거를 유지합니다.
- 중지는 실제 상태 전환과 연결 진단을 처리하고, 다시 시도는 같은 목표의 새 실행을 만듭니다.
- 일시 중지·모델 연결 대기·입력 대기에는 같은 ID의 체크포인트를 명시 재개합니다. 종료·프로세스 강제 종료를 자동 재실행하지 않으며 같은 도구 ID와 인자 해시의 영수증을 재사용합니다.
- 제어 요청 expected_updated_at에는 control_updated_at을 전달합니다. 원래 실행 주체의 현재 키·역할·서비스·범위·정책과 누적 한도를 재검사합니다.
- 선택 검색·임베딩·Graphiti·모델 플랫폼·격리 실행·관측성은 기본 꺼짐입니다. 모두 실패해도 일반 업무를 중단하지 않으며 모델만 없으면 재개 가능한 대기로 처리합니다.
- 모델 부분 답변은 성공 커밋 전에 폐기합니다. 실패 제공자의 텍스트·도구를 다른 제공자와 합치지 않고 UTF-8 마스킹·8192바이트 SSE 경계를 유지합니다.
- 검색·그래프 결과는 실행 지시가 아닙니다. 원격 그래프 원문 대신 현재 권한·로컬 ID/해시가 확인된 기억만 반환합니다.
- 격리 진단은 profile=isolated와 execution_profile_id로 같은 Hunter 이미지의 고정 프로브만 실행합니다. mTLS·고정 digest·정확한 망·현재 정책, 생성 이후 불명 작업 중복 금지를 유지합니다.
- 관측에는 마스킹한 수치·안전한 식별자만 비동기 전송합니다. 프롬프트·도구 인자·결과·증거는 관측 payload에 넣지 않습니다.
- GraphQL은 인증된 query만, 깊이8·필드500·복잡도10000·100행 페이지·총성공JSON4MiB 한도를 유지합니다. 별칭·JSON escape·봉투를 projection 중 보수적으로 계산하고 초과 시 400/QUERY_LIMIT·data:null로 거부합니다. 보고서는 현재 상태·잘림 한도·오프라인 한글 폰트를 포함합니다.
- 모델 완료·진단 실패·결과에서 사라짐을 발견 건의 자동 확인·해결 조건으로 사용하지 않습니다.
- 네트워크 진단에는 승인 서비스·유효 범위·현재 정책이 항상 필요합니다.
- 팀장 검토·승인·반려는 관리자 설정이 켜졌을 때만 적용하며 대상 범위 승인과 구분합니다.
- 대상 DNS·주소·경로·리다이렉트·요청량 검사를 우회하는 새 도구나 연동을 만들지 않습니다.
- 알림 자동화·채널 운영·변경 규칙은 기본 비활성, 같은 PostgreSQL과 제어 서버에서 처리합니다. 워커 전용 실행에 발송 루프를 넣지 않습니다.
- 동적 수신자·개인함은 현재 계정·역할·키·팀·부모 권한과 묶음 전체 자료의 접근을 다시 검사합니다.
- 접수·전달·ACK·승인·해결을 분리합니다. 불명 자동 재발송·동일 ID receipt 재시도·새 설정으로 과거 receipt 재해석을 금지합니다.
- Hunter 서명 콜백은 타임스탬프와 원문 바이트를 검증합니다. 벤더·Git 콜백을 직접 호환한다고 가정하지 않습니다.
- 변경 규칙은 실제 변경 목록과 현재 정책으로 검사만 선택하며 ITSM 완료만으로 발견 건을 해결하지 않습니다.
- ITSM은 외부 버전·로컬 기준·revision을 검사합니다. 명시 대체는 확인 당시 로컬/외부 revision+원래 외부 hash를 고정하고 배포 확인에만 허용 재검증합니다.
- 보존 작업은 진행·불명·미확인·보존 고정·미정 receipt를 제외하고 본문을 파기해도 중복 식별 기록을 남깁니다.
- 외부 발송은 접수와 수신을 구분합니다. 알림은 admin:manage·암호화 큐·시도 한도를 지키며 결과 불명 재발송은 명시적 중복 위험 확인을 요구합니다.
- 외부 스캐너 JSON 수입과 실제 내장 HTTP·권한 진단의 제공 범위를 정확히 설명합니다.
- 캠페인 시작은 정책 준비 후 트랜잭션에서 일괄 삽입합니다. 풀 조회와 잠금 대기의 연결 고갈을 피합니다.
- 실행 스냅샷을 덮어쓰지 않으며 외부 수입·실패·조건 변경·이전 실행을 비교해 자동 해결하지 않습니다.
- KEV·EPSS·SBOM은 한도를 검증해 반입하고 EPSS null과 0, 라이선스 검토와 적합성 확정을 구분합니다.
- 구조형 evidence는 거부하며 과거 자료 복구는 키 검사 후 서버 시작 전에 완료합니다. 잠긴 미복구 행을 무시하지 않습니다.
## 7. 개발과 회귀 검증

Go 1.26.5 이상과 Node.js 26을 사용하고 잠금 파일로 의존성을 설치합니다.
프런트엔드를 바꾼 뒤 Go 실행 파일을 검증할 때는 최신 빌드 결과를 다시 포함합니다.

```sh
npm --prefix web ci
npm --prefix web test
npm --prefix web run build
mkdir -p internal/webassets/dist
cp -a web/dist/. internal/webassets/dist/
go vet ./...
go build ./cmd/hunter
```

- `gofmt`는 변경한 Hunter Go 파일에만 적용합니다. `gofmt -w .` 같은 원본 포함 일괄 실행은 피합니다.
- 현재 테스트 수와 실패·건너뜀 여부를 실행 결과로 확인하고 변경된 실패 경로의 회귀 검증을 포함합니다.
- 인증·키·팀 격리·승인·재검증·예약·중지·스트리밍 변경에는 해당 실패 경로의 회귀 검증을 수행합니다.
- 동작과 무관한 문구·단순 스타일 변경에 구현을 그대로 반복하는 테스트를 추가하지 않습니다.
- PostgreSQL 테스트는 `HUNTER_TEST_DSN`이 없으면 건너뛸 수 있습니다. skip을 DB 검증 통과로 보고하지 않습니다.
- 아래 값은 치환용 예시입니다. 격리된 테스트 DB를 준비하고 실제 비밀은 안전한 로컬 주입 방식으로 제공합니다.

```sh
HUNTER_TEST_DSN='postgres://<TEST_USER>:<TEST_PASSWORD>@<TEST_HOST>:5432/<TEST_DB>?sslmode=disable' \
  go test -race -count=1 ./...
```

`HUNTER_TEST_DSN`은 테스트 전용이며 다섯 번째 서비스 런타임 설정이 아닙니다.
기존 테스트의 격리 스키마 도우미를 사용하고 공유 DB의 `public` 스키마나 운영 자료를 삭제하지 않습니다.
관련 테스트 통과 뒤에는 새 변경이나 미해결 실패가 없는 한 같은 검사를 반복하지 않습니다.
## 8. 원본·라이선스와 이미지 검사

출력 디렉터리는 새 빈 디렉터리를 사용합니다. 이전 결과와 섞거나 누락을 무시하지 않습니다.

```sh
node scripts/verify-pentagi.mjs
go run ./scripts/license-notices -out dist/licenses
node scripts/collect-web-licenses.mjs dist/npm-licenses
bash -n scripts/release.sh
python3 -m py_compile scripts/release-notes.py
```

- Go·코어·폰트 출처는 이미지의 `/usr/share/licenses/hunter/dependencies.json`에 보존합니다.
- npm 출처는 `/usr/share/licenses/hunter/npm/manifest.json`과 `npm/components/`에 보존합니다.
- 보고서 NanumGothic TTF·OFL 출처 해시도 고정하고 외부 PDF 실행 파일 없이 Go에서 생성합니다.
- 고지 누락 시 수집을 실패시키며 라이선스 원문이나 저작권자를 임의로 작성하지 않습니다.
- 보충 근거는 고정 출처·해시와 구분 설명을 함께 기록합니다.
- 이미지 검증은 외부 통신이 차단된 망, 일반 PostgreSQL, 필요한 사내 모의 AI로 수행합니다.
- 네 환경변수·비특권·읽기 전용·소켓 미노출 조건에서 시작·실제 경로·재시작 후 보존을 확인합니다.
## 9. 화면과 문서

- 메뉴·버튼·오류는 한국어와 Mantine 체계를 따릅니다. 새로고침 메뉴·탭과 로그인·프로필 버전을 확인합니다. OIDC auto/mode/return context의 state·nonce·PKCE·1회 소비와 10분 억제·logout24h·local=1 복구를 유지하고 ReSSO 실환경 호환을 추정하지 않습니다.
- 목록 검색·필터·정렬·페이지는 URL에 보존하고, 다른 상세 링크 매개변수를 지우지 않습니다.
- 검색 인덱스에는 명시적으로 선택한 표시 필드만 사용하며 비밀값이나 전체 API 응답을 직렬화하지 않습니다.
- 즐겨찾기·최근 방문은 사용자별로 분리하고 현재 권한과 관리자 승인 메뉴 설정을 적용합니다.
- 저장한 목록 보기는 사용자·메뉴별로 분리하고 허용된 목록 조건만 보관합니다. 상세 ID·임의 URL 매개변수·폼 초안·비밀값을 저장하지 않습니다.
- 설정 저장 후에는 저장한 그룹만 갱신하고 다른 그룹의 작성 중인 값을 덮어쓰지 않습니다.
- 모바일 메뉴가 닫혔을 때 숨겨진 항목에 초점이 들어가지 않아야 합니다. 화면 이동과 팝업 닫힘의 초점 복귀를 함께 확인합니다.
- 데스크톱과 모바일에서 글자 크기, 가로 넘침, 스크롤바, 오류·빈 상태를 확인합니다.
- 변경한 페이지는 실제 앱에서 캡처하고 문서용 합성 자료임을 설명합니다. 추적은 기본off·관리자 세션 전용·암호화 revision·opaque iframe과 고정 path/title만 사용하며 로그인/admin/personal·사용자/자료ID·쿼리를 제외합니다. 앱 전체 CSP를 완화하지 않고 preview5분1회를 유지하며 준비와 수집기 접수를 구분합니다.
- 모의 AI·SMTP·HTTP 검증을 실모델 품질·공급 계정 발송·단말 수신으로 표현하지 않고, 외부 실수신자에게 시험 발송하지 않습니다.

```sh
npm --prefix docs ci
npm --prefix docs exec -- playwright install chromium
node scripts/render-guides.mjs
node scripts/check-docs.mjs
git diff --check
```

가이드 Markdown 변경 후 HTML·PDF를 재생성합니다. 문서 링크·이미지·한글 PDF·모바일·홍보 버전·FAQ·JSON-LD를 확인합니다.
검증 기록은 수행한 환경과 한계를 명시하며 현재 제공 기능과 후속 확장을 구분합니다.
## 10. 버전·커밋·배포 완료 기준

- `VERSION`, 웹·문서 패키지 버전, 가이드·홍보·배포 예시를 함께 맞춥니다.
- 이미지 태그는 `hunter:v버전`, 유일한 릴리즈 첨부는 `hunter-v버전.tar.gz`입니다.
- `scripts/release.sh`는 `VERSION`을 검사하고 `linux/amd64` 서비스 이미지만 save·gzip 합니다.
- PostgreSQL·별도 실행 이미지·PDF·체크섬 파일을 추가 릴리즈 자산으로 첨부하지 않습니다.
- 체크섬은 릴리즈 본문에 기록하고 GitHub 자동 소스 다운로드와 첨부 자산을 구분합니다.
- 검증된 변경만 선별해 커밋하고 push 후 CI, 버전 태그 릴리즈와 Pages 배포 결과를 확인합니다.
- 이미 사용자가 승인한 커밋·푸시·릴리즈를 이 문서 때문에 다시 확인받거나 중단하지 않습니다.

```sh
bash scripts/release.sh "$(cat VERSION)"
gh run list --limit 5
gh release view "v$(cat VERSION)" --json tagName,assets,url
```

완료 보고에는 실제 변경, 통과한 검증, 미검증 한계와 배포 URL·태그를 간결하게 기록합니다. 단순히 명령을 시작한 상태를 CI·릴리즈·GitHub Pages 배포 완료로 보고하지 않습니다.
