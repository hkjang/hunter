# Hunter PentAGI 코어 통합과 v1.8 확장

최종 갱신: 2026-09-13. Hunter는 PentAGI의 고정 원본 코어를 내장하고, 서비스별 에이전트 진단을 기존 권한·진단 정책과 연결합니다. 이 문서는 구현된 연결 방식, 보존한 라이선스, 데이터 저장 범위와 검증 근거를 설명합니다. 원본 파일 해시·코어 통합·Hunter 실행 경로의 자동 테스트는 통과했으며, 7장은 최초 v1.1 통합의 검증 기록입니다. v1.8 선택 연동·체크포인트·보고서·GraphQL의 현재 계약은 [에이전트 플랫폼](agent-platform-v180.md)과 [검증 기록](../validation.md)을 함께 확인합니다.

## 1. 실제 포함한 원본과 연결 계층

기준 원본은 [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi/tree/ea665308baaff015b226f308438a68d929d0f29b)의 커밋 `ea665308baaff015b226f308438a68d929d0f29b`입니다. 변경일은 2026-08-06이고 커밋 제목은 `fix(deps): upgrade langchaingo version to release version v0.1.14-update.7`입니다. 가변적인 `main`이나 `latest`를 빌드 시 내려받지 않습니다.

| 위치 | 포함 내용 |
| --- | --- |
| `third_party/pentagi/backend` | `pkg/providers`의 의존 패키지와 템플릿을 포함한 `pentagi` Go 모듈 |
| `third_party/pentagi/UPSTREAM.json` | 원본 저장소·커밋과 원본 312파일의 SHA-256 |
| `third_party/pentagi/backend/pkg/providers/hunter_bridge.go` | 원본 모듈 안에 추가한 Hunter 연결 파일 |
| `internal/pentagicore` | 모델·도구·이벤트 연결, 호환 SQL 저장소와 코어 실행 |
| `internal/app/agents*.go` | Hunter 인증·권한·실행 한도·SSE·진단·후보·메모리 연결 |
| `web/src/agents.tsx` | 에이전트 실행 목록과 상세 화면 |

원본 312파일은 해당 커밋의 내용과 동일하며, 추가한 bridge와 Hunter 연결 코드는 구분되어 있습니다. `go.mod`의 `replace pentagi => ./third_party/pentagi/backend`로 이 모듈을 사용합니다. [출처 설명](https://github.com/hkjang/hunter/blob/main/third_party/pentagi/README.hunter.md)에 보존한 원본 동작과 연결 범위를 기록했습니다.

실행에는 원본 하위 작업 생성·구체화, 여러 차례의 도구 호출 처리, 역할 위임, 계획 조언·성찰, 재시도, 작업 보고와 대화 요약 코어를 사용합니다. 모델 API는 Hunter의 인증된 스트리밍 연결을 사용하고, 실제 서비스 관련 행위는 5장의 여덟 Hunter 도구로 수행합니다.

## 2. PentAGI 자체 라이선스와 EULA

고정 커밋의 [LICENSE](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/LICENSE)는 MIT이며 저작권자는 `Copyright (c) 2025 PentAGI Development Team`입니다. 원문은 사용·복사·수정·병합·배포 등을 허용하고, 사본 또는 상당 부분에 저작권 및 허가 고지를 포함하도록 정합니다. Hunter의 자체 MIT 고지만으로 원본 저작권 고지를 대체하지 않습니다.

같은 커밋의 [EULA.md](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/EULA.md)는 소스, 사전 빌드 이미지와 UI에 관한 추가 조건을 기술합니다. 그 문서의 License Grant에는 충돌이 있으면 **소스 코드에 대해서는 MIT 조건이 우선한다**고 적혀 있습니다. 원본 배포 형태 전체를 MIT 파일 하나만으로 설명하는 것은 정확하지 않습니다. 이식한 소스의 출처 기록에는 EULA 원문도 함께 보존하고, 그 사실을 Hunter 자체의 별도 라이선스 변경이나 새 동의 절차로 표현하지 않습니다.

이는 확인한 원문의 내용과 재배포 준비에 관한 기술 기록입니다. 개별 계약의 효력이나 모든 제3자 권리 문제를 일괄 판단하는 문서는 아닙니다.

## 3. Cloud SDK의 NOTICE 불일치 확인

PentAGI의 [NOTICE](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/NOTICE)는 Cloud SDK를 AGPL-3.0과 공식 PentAGI 예외로 설명합니다. 반면 같은 커밋의 [go.mod](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/backend/go.mod)는 `github.com/vxcontrol/cloud v0.9.0`을 지정합니다. 이 **실제 Go 모듈 ZIP의 LICENSE, doc.go와 하위 파일**을 직접 확인했습니다.

| 검토 항목 | 확인 결과 |
| --- | --- |
| SDK 버전 | `github.com/vxcontrol/cloud v0.9.0` |
| 실제 소스 커밋 | `8288952770385bd4f4b31c1a503c66da965ab6c9` |
| 모듈 합계 | `h1:p7xYTgUctbY8w6YfhugNzvfi3/0EQoZGumMe67keAng=` |
| 원본과 일치 여부 | PentAGI 고정 커밋의 `backend/go.sum` 값과 일치 |
| LICENSE | MIT, `Copyright (c) 2026 PentAGI Development Team` |
| 추가 하위 라이선스 | 확인한 모듈 내 별도 하위 LICENSE·NOTICE·AGPL 예외 파일 없음 |

근거는 SDK의 고정 커밋 [LICENSE](https://github.com/vxcontrol/cloud/blob/8288952770385bd4f4b31c1a503c66da965ab6c9/LICENSE)와 [doc.go](https://github.com/vxcontrol/cloud/blob/8288952770385bd4f4b31c1a503c66da965ab6c9/doc.go)입니다. 따라서 고정 버전의 코드 출처 설명에는 실제 MIT 라이선스를 사용하고, PentAGI NOTICE의 AGPL 문구가 해당 의존 버전의 실물과 일치하지 않는다는 주석을 별도로 남깁니다. 공식 프로젝트 전용 예외를 Hunter에 이전받았다고 주장하지 않습니다. 원본 NOTICE를 보존할 때도 이 설명을 함께 제공합니다.

SDK 코드와 VXControl Cloud 서비스 접근은 별개입니다. SDK의 [TERMS_OF_SERVICE.md](https://github.com/vxcontrol/cloud/blob/8288952770385bd4f4b31c1a503c66da965ab6c9/TERMS_OF_SERVICE.md)는 범위를 서비스·API·데이터 접근으로 정하고, SDK의 MIT와 구분합니다. 해당 서비스의 데이터 재배포, 상업 이용과 접근 자격을 SDK의 MIT 권리로 간주하지 않습니다. Hunter의 폐쇄망 기본 구성은 이 외부 서비스를 필수 의존성으로 추가하지 않습니다.

## 4. 실제 의존성과 별도 구성요소

아래 Go 모듈은 현재 빌드 의존성에 포함됩니다. 정확한 버전의 다운로드 결과와 LICENSE를 확인했으며, 라이선스 수집기는 해당 원문을 함께 보존합니다. 패키지 의존성에 포함된 코드와 실행 시 초기화하는 외부 서비스는 구분됩니다.

| 구성요소 | 확인한 소스·라이선스 | Hunter에서의 처리 |
| --- | --- | --- |
| `github.com/vxcontrol/cloud v0.9.0` | 커밋 `8288952770385bd4f4b31c1a503c66da965ab6c9`, MIT | SDK 고지 보존, 외부 Cloud 서비스 초기화 없음 |
| `github.com/vxcontrol/langchaingo v0.1.14-update.7` | 커밋 `da7016e399b04d3a4fc9eef54aa6ce053b46d3b9`, MIT | Travis Cline 및 2025 PentAGI Development Team 저작권 보존 |
| `github.com/vxcontrol/graphiti-go-client v0.9.0` | 커밋 `4984df2b6629f7640644e5213db1220b8baf473e`, MIT | Go 의존성 고지 보존, Graphiti 서버 초기화 없음 |
| `github.com/richardlehane/msoleps v1.0.1` | 소스 헤더의 Apache-2.0·2014 Richard Lehane 저작권 | 독립 LICENSE가 없는 모듈이므로 고정 소스 해시를 검사하고 원문 헤더·공식 Apache 전문 보존 |
| 원본 프런트엔드 폰트·APOC 예제 JAR | 각각 별도 OFL·Apache 라이선스 | Hunter 코어 통합의 배포 자료에 포함하지 않음 |
| 원본 Compose의 별도 이미지 | scraper·pgvector·Graphiti·Neo4j·Langfuse·관측 구성요소 | Hunter 이미지에 번들하거나 자동 기동하지 않음 |

모듈 근거: [Langchaingo LICENSE](https://github.com/vxcontrol/langchaingo/blob/da7016e399b04d3a4fc9eef54aa6ce053b46d3b9/LICENSE), [Graphiti Go client LICENSE](https://github.com/vxcontrol/graphiti-go-client/blob/4984df2b6629f7640644e5213db1220b8baf473e/LICENSE), [msoleps 소스 헤더](https://github.com/richardlehane/msoleps/blob/v1.0.1/msoleps.go). 원본 폰트·예제의 라이선스는 [폰트 안내](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/frontend/public/fonts/README.md)와 [APOC 동봉 LICENSE](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/examples/neo4j/plugins/LICENSE.txt)에서 확인했습니다.

원본 `licenses/`에는 README만 있고 원본 [Dockerfile](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/Dockerfile)의 Go 라이선스 CSV 생성은 `|| true`로 실패를 무시합니다. Hunter는 실제 Go 컴파일 의존성에서 라이선스 원문과 출처·해시 목록을 별도로 수집합니다. 따라서 원본의 빌드 성공이나 의존성 설명만으로 고지 완비를 판단하지 않습니다.

## 5. 실행 기능, 권한과 한도

사용자는 `/agents`에서 서비스와 진단 목표를 지정합니다. `/agents/:id`의 목표와 결과·에이전트 응답·도구 호출·실행 기록·연결된 진단 탭에서 진행 상황을 확인합니다. 탭 선택은 URL에 보존됩니다. 브라우저의 SSE 연결이 끊겨도 서버 실행은 계속되며 마지막 이벤트 ID 다음부터 기록을 다시 동기화합니다.

| Hunter 도구 | 실제 기능 |
| --- | --- |
| `service_context` | 현재 서비스·허용 범위·지원 기능 조회 |
| `list_findings` | 현재 서비스의 허용된 발견 건 조회 |
| `request_scan` | 승인된 제한 진단 요청 |
| `scan_result` | 진단의 실제 상태와 결과 조회 |
| `record_candidate` | 확인되지 않은 발견 후보 기록 |
| `remember` | 사용자·서비스 범위의 분석 메모 저장 |
| `recall` | 같은 범위의 분석 메모 검색 |
| `search_reference` | 관리자 선택 공급자의 비신뢰 참고 자료 검색 |

목록·상세·SSE 이벤트 조회에는 `agents:read`, `services:read`, `findings:read`, `scans:read`를 모두 요구합니다. 실행 기록에 포함되는 서비스·발견 건·진단 결과의 자료 권한을 함께 확인합니다. 생성에는 추가로 `agents:write`와 `ai:use`를 요구하고 실행 중에도 현재 권한·개인 키와 서비스 범위를 재검사합니다. 허용 범위는 직접 선택하거나 서버가 유효한 승인 범위를 자동 선택하며, 자동 선택도 기존 승인·만료 검사를 통과해야 합니다.

관리자 `agents` 설정은 기본 비활성화입니다. 기본 상한은 역할별 원본 에이전트 체인 호출당 반복 24회, 실행당 모델 호출 60회, 여덟 Hunter 도구 호출 40회, 실행 시간 15분입니다. 내부 역할 위임은 Hunter 도구 호출 수에 포함하지 않습니다. 진단 요청 도구는 기본 금지이며 후보 기록과 기억 기능은 기본 허용입니다. 현재 설정과 실행 시작 시 허용 범위를 모두 적용합니다.

목표는 32,000바이트 이내이고 사용자당 진행 중인 실행은 최대 3개입니다. 목록은 접근 가능한 최신 1,000건, 메모리는 사용자·서비스별 최대 100개를 관리합니다. 중지는 해당 실행과 연결된 진행 중 진단의 중단을 요청하며 이미 저장된 후보나 완료된 작업을 자동 복원하지 않습니다. 다시 시도는 같은 목표의 새 실행을 생성합니다. v1.8에서는 안전 경계에 저장한 체크포인트를 일시 중지·입력 대기·모델 연결 대기에서 명시 재개합니다. 같은 실행 ID와 누적 모델·도구·활성 시간 한도를 유지하며 종료·프로세스 강제 종료는 자동 재실행하지 않습니다. 역할 체인 호출별 반복은 재개 시 새 호출에 적용합니다.

원본 `ask` 경계에서 추가 확인이 필요하면 입력 대기로 남기고, 새 입력을 저장한 뒤 같은 실행을 명시 재개합니다. 모델·도구·시간 예산을 초과한 실행은 성공으로 단정하지 않고 해당 종료 상태를 남깁니다. 모델이 작업 성공을 보고해도 발견 건을 자동 확인·해결하지 않습니다. 후보와 실제 진단 결과를 구분하고 기존 검토·재검증 절차를 적용합니다.

## 6. PostgreSQL, 배포와 고지 파일

공개 런타임 환경변수는 `POSTGRES_DSN`, `BOOTSTRAP_ADMIN`, `BOOTSTRAP_ADMIN_PASSWORD`, `ENCRYPTION_KEY` 네 개입니다. 에이전트·AI·권한·정책은 관리자 화면에서 설정합니다. 별도 필수 서비스나 추가 실행 이미지를 요구하지 않는 Hunter 연결 계층을 사용합니다.

| 원본 구성 | Hunter 구현 |
| --- | --- |
| 시작 시 Docker 클라이언트·데몬 정보 조회 | 원본 Docker 런타임 초기화 없음 |
| Docker 소켓 마운트·root 실행·실행 이미지 가져오기 | 소켓 미노출, 비특권 사용자, 서비스 이미지 하나 |
| 전체 마이그레이션의 `vector`, `pg_trgm` 사용 | 일반 PostgreSQL의 별도 스키마와 호환 테이블·체크포인트 |
| 외부 scraper·Graphiti·Neo4j·Langfuse | 서버 번들·자동 기동 없음. v1.8 관리자 선택 어댑터 연결 |
| 인터넷 검색 기본값과 공급자 탐색 | 원본 도구·자동 탐색 미등록. v1.8 Hunter 선택 검색·모델 어댑터 사용 |
| Go 1.26.5 이상 요구 | 고정 다이제스트의 Go 1.26.8 빌드 이미지 사용 |

원본 차이를 확인한 코드: [Docker 시작](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/backend/cmd/pentagi/main.go#L172), [이미지 가져오기](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/backend/pkg/docker/client.go#L1172), [DB 확장](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/backend/pkg/database/tenant.go#L16), [기본 Compose](https://github.com/vxcontrol/pentagi/blob/ea665308baaff015b226f308438a68d929d0f29b/docker-compose.yml).

`internal/pentagicore/schema.sql`은 분리된 PostgreSQL 스키마의 `flows`, `tasks`, `subtasks`, `msgchains`, `msglogs`와 Hunter 체크포인트를 준비합니다. 추가 SQL 연결은 최대 두 개입니다. 사용자 화면 이벤트·메모리·발견 증거는 Hunter 암호화 저장소를 사용합니다. 코어 대화 기록에는 마스킹된 질문·도구 결과와 모델의 비공개 추론이 포함될 수 있고 별도의 필드 암호화를 적용하지 않습니다. 이 기록은 일반 UI 이벤트에 노출하지 않으며 DB와 백업의 접근 통제로 보호합니다. 모델 API 키는 대화나 코어 기록에 넣지 않습니다.

소스 저장소에는 다음 파일을 보존했습니다.

- `third_party/pentagi/LICENSE`, `NOTICE`, `EULA.md`: 원문 고지
- `third_party/pentagi/UPSTREAM.json`: 원본 커밋과 파일 해시
- `third_party/pentagi/README.hunter.md`: 원본 보존 범위와 연결·저장소 제약
- `scripts/license-notices/PENTAGI-NOTICE.md`: Cloud SDK NOTICE 불일치 설명
- `scripts/license-notices/overrides/msoleps-v1.0.1/`: 고정 소스에 근거한 보충 라이선스 원문

Dockerfile과 CI는 `scripts/verify-pentagi.mjs`로 원본 해시를 검증합니다. `scripts/license-notices`는 실제 Go 의존성의 LICENSE·NOTICE·COPYING, Hunter·Go·번들 폰트 고지와 파일 해시 목록을 수집하고 필수 고지가 없거나 비어 있으면 실패합니다. 코드 파일인 `license.go` 등은 고지로 복사하지 않습니다. 출력은 새 디렉터리에서 생성하여 이전 빌드의 파일을 혼합하지 않습니다.

Dockerfile은 생성된 고지 디렉터리를 `/usr/share/licenses/hunter/`로 복사합니다. 이 경로에는 `dependencies.json`, `PENTAGI-NOTICE.md`, 원본 고지·출처 명세와 모듈별 라이선스 원문이 들어갑니다. 프런트엔드 npm 고지는 `/usr/share/licenses/hunter/npm/manifest.json`과 `npm/components/`에 별도 보존합니다. `scripts/collect-web-licenses.mjs`는 실제 설치된 운영 의존성 45개와 고지·출처 근거를 수집하며 필수 고지나 감사한 보충 근거가 누락되면 실패합니다. 이는 Go·코어·폰트 수집기와 별도 집계이며 v1.8의 실제 수집 결과는 149개입니다. 보고서의 NanumGothic OFL·고정 출처도 포함합니다. 원본 전체 소스를 런타임에 복사하지 않습니다. 릴리즈 첨부는 `hunter:v버전` 서비스 이미지를 압축한 `hunter-v버전.tar.gz` 한 개이며 고지는 이미지 안에 포함됩니다.

## 7. 검증 근거와 배포 검증 상태

2026-09-12 기준 다음 자동 검증이 통과했습니다. 코어와 Hunter 실행 테스트는 테스트용 PostgreSQL 및 모의 스트리밍 모델을 사용하므로 임의 실모델·운영 대상에 대한 성능이나 탐지율을 뜻하지 않습니다.

| 검증 | 확인한 범위 |
| --- | --- |
| 전체 Go 테스트·정적 검사 | PostgreSQL 환경에서 `go test -race -count=1 ./...` 통과, 전체 실행 시 테스트 함수 45개 통과 후 긴 한글 응답 회귀 테스트를 추가하여 총 46개, 해당 테스트와 HTTP 코어 테스트의 추가 `-race` 실행 통과, `go vet ./...` 통과 |
| `verify-pentagi.mjs`, `TestPinnedOriginalCoreUnchanged` | 원본 312파일의 고정 SHA-256 일치 |
| `TestOriginalPlannerDelegationToolLoopAndReporter` | 원본 계획·위임·도구 반복·보고 경로 실행 |
| `TestSafeToolsEnforceRevocationAndDedupe`, `TestModelBudgetStopsBeforeExtraCall` | 도구 권한 철회·중복 방지·모델 요청 예산 |
| `TestCoreSchemaAndRunIdentityIsolation` | 호환 스키마와 동일 실행 ID 보호 |
| `TestAgentOriginalCoreThroughStreamingHTTPAndSSE` | 실제 Hunter HTTP 경로에서 원본 코어와 스트리밍 모델·SSE 연결 |
| Hunter 에이전트 권한·중지·마스킹 테스트 | 조회 자료 권한, 실행 권한 철회, 중지와 연결 진단, 스트리밍 비밀정보 마스킹 |
| 실제 브라우저 흐름 | 웹에서 생성 → 코어 도구 4회·모델 13회 → 완료, 같은 목표 새 실행 → 중지됨 전환 |
| 상세 화면 반응형 검증 | 1512px·390px에서 다섯 탭의 가로 넘침·페이지 오류 없음, 새로고침 시 탭 유지 |
| 프런트엔드 단위 테스트 | 테스트 10개 통과 |
| SSE 강제 끊김·중복 복구 | 이벤트 연결의 `after=0` 이후 끊김과 `after=3` 재연결·중복 주입에서 실제 71개 이벤트를 화면에 71개로 복구 |
| 라이선스 수집 검증 | Go 의존성과 번들 구성요소 고지 생성, 해시 일치, Go 원본 파일 미포함 |

검증 소스: [코어 통합 테스트](https://github.com/hkjang/hunter/blob/main/internal/pentagicore/engine_test.go), [Hunter 실행 테스트](https://github.com/hkjang/hunter/blob/main/internal/app/agents_test.go), [스트리밍 마스킹 테스트](https://github.com/hkjang/hunter/blob/main/internal/app/agents_redaction_test.go).

브라우저 검증도 로컬 SSE 모의 모델을 사용했습니다. 실제 실행한 도구는 `service_context`, `list_findings`, `remember`, `recall`이며, 이 사례에서 실제 대상 진단이나 실모델 품질을 검증했다고 해석하지 않습니다.

별도의 Docker `--internal` 네트워크에서 일반 PostgreSQL, 로컬 SSE 모의 모델과 승인된 합성 HTTP 대상을 연결하여 서비스 이미지의 폐쇄망 실행을 검증했습니다. 공개 환경변수 네 개만 전달했고 읽기 전용 파일 시스템, UID 10001, `cap-drop ALL`, `no-new-privileges`, Docker 소켓·볼륨 마운트 없이 실행했습니다. 외부 HTTP 접근은 차단됐습니다.

이 검증에서는 모델 호출 22회와 일곱 Hunter 도구를 모두 실행했고, 승인된 합성 대상에 실제 GET 요청 1회가 도달했습니다. 원본 코어의 대화 체인 9종이 보존되었으며 PostgreSQL 확장은 기본 `plpgsql`만 사용했습니다. SSE의 비밀정보 마스킹, 이벤트·메모리의 암호화 저장을 확인했고 서비스 재시작 후 실행·작업·진단·발견 후보·AI 설정이 유지됐습니다. 이는 통제된 합성 대상의 연결·실행 검증이며 외부 스캐너 전체 기능이나 실제 취약점 탐지율을 검증한 결과는 아닙니다.

검증 이미지 안에서 `/usr/share/licenses/hunter/` 고지 파일도 확인했습니다. Go 의존성 고지 집계와 프런트엔드 npm 번들 고지 집계는 구분하며, 최종 배포 파일 수는 실제 릴리즈 이미지의 출처 명세를 기준으로 확인합니다. 배포·게시 상태의 최종 기록은 [릴리즈 검증](../validation.md)에 따릅니다.
