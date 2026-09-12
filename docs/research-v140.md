# Hunter v1.4 운영 기능 조사와 채택 범위

조사일: 2026-09-12, Asia/Seoul. 비교 기준은 Hunter v1.3.0, 커밋 `1c5a860d85b8f5fbb50bd07248f8ab734e9a227d`입니다. 공식 자료 조사 후 아래 일곱 운영 기능을 v1.4.0의 Hunter 자체 코드로 구현했습니다. 이 문서는 조사 근거와 실제 채택 범위를 구분합니다. 수행한 테스트와 배포 검증은 [검증 기록](validation.md), 사용 절차는 사용자·관리자 가이드에서 확인합니다.

DefectDojo, Dependency-Track, ProjectDiscovery, Faraday의 공식 문서와 공식 GitHub 저장소·이슈를 확인했습니다. 공개 문서에 소개된 기능은 제품 에디션과 버전에 따라 다르며, 아이디어를 참고한다는 사실이 해당 제품의 코드나 상용 기능을 Hunter에 포함한다는 뜻은 아닙니다.

## 구현한 운영 흐름

**SBOM·위협 정보 반입 → 영향 서비스와 조치 우선순위 확인 → 담당자 조치·공통 원인 협업 → 캠페인 진단·이전 결과 비교 → 근거 있는 재검증**을 한 흐름으로 연결합니다. 관리자 운영 점검은 이 과정에서 오래된 자료, 실행 대기, 워커 응답 지연, 연동 기능의 사용 설정 여부를 확인하도록 돕습니다.

이미 있는 검색·정렬·필터, 위험 수용 만료, 중복 관찰, 단일 진단 예약, 개인 키 회전은 재구현 대상에서 제외합니다. 실제 채택 범위는 아래 일곱 기능입니다. 기존 PentAGI 원본 312개 파일과 고정 출처는 변경하지 않았습니다.

## 조사 당시 Hunter v1.3의 기반과 확장 지점

비교 대상: [README](../README.md), [사용자 가이드](guides/user-guide.md), [관리자 가이드](guides/admin-guide.md), [OpenAPI](../internal/app/openapi.json), `internal/app/domain.go`, `imports.go`, `worker.go`, `domain_schedules.go`, `web/src/resources.tsx`.

| 운영 영역 | 이미 있는 기능 | 이번에 연결할 부분 |
| --- | --- | --- |
| 조치 관리 | 발견 건의 `assignee`, `due_date`, 상태와 위험 수용 만료 | 정책에서 기한 산정, 등록자·기한 기준 조치함, 임박·초과 분류 |
| 위험 정보 | `cve`, 기술적 심각도, 서비스 중요도 | KEV·EPSS 반입 이력과 데이터 기준일, 설명 가능한 운영 우선순위 |
| 구성요소 | 발견 건의 `component` 문자열과 관계 그래프 | 서비스 버전별 SBOM 구성요소·의존 관계·라이선스·변경 비교 |
| 실행 관리 | 단일 진단, 예약, 망별 워커, 관찰 기록과 재검증 | 여러 서비스를 묶은 캠페인, 실행별 결과 집합과 기준 실행 비교 |
| 협업 | 발견 건 수정, 감사 기록, 개선 초안 발송 | 발견 건 댓글·저장 감사·최근 관찰·현재 재검증 타임라인 |
| 공통 원인 | 서비스와 fingerprint 기반의 동일 결과 중복 판정 | 서로 다른 서비스의 발견 건을 보존하는 공통 원인 후보 |
| 운영 상태 | 기본 health, 워커, 이벤트, 긴급 중지 | 큐·워커·반입 자료·연동 사용 설정을 모은 관리자 점검 화면 |

현재 목록과 일부 집계에는 종류별 최신 5,000건 조회 한도가 있습니다. v1.4 조치함은 서버에서 전체 접근 범위의 검색·집계·페이지를 처리하고, SBOM·캠페인은 전용 조회 경로를 사용합니다. 기존 관찰 기록은 최근 100개로 제한되므로 캠페인 비교용 관측 집합을 실행별로 따로 보존합니다.

## 1. SLA와 조치함

**조사 근거.** DefectDojo의 심각도별 조치 기한, 남은 일수·초과 상태, 재반입·재활성화 기한 규칙을 참고했습니다. 문서의 일부 관리·위험 기반 기준은 Pro로 표시됩니다. [SLA Configuration](https://docs.defectdojo.com/asset_modelling/os_hierarchy/os__sla_configuration/)

**구현.** `/triage`의 조치함은 현재 접근 가능한 미조치 발견 건을 운영 우선순위·기한 순으로 조회하고 서버 검색·집계·페이지를 제공합니다. 수동 `due_date`가 우선이며, SLA를 켜면 수동 기한 없는 건에 생성 시각+심각도별 일수를 적용합니다. 정책은 기본 꺼짐이며 관리자 화면에 저장합니다. 재반입으로 최초 기한을 연장하지 않습니다.

**범위.** '내가 등록한 발견 건'은 발견 건 소유자 기준이고 자유 입력 `assignee`와 사용자 계정을 자동 매칭하지 않습니다. SLA는 조회 시 계산하며 정책 변경의 이전 산정값을 별도 이력 테이블에 저장하지 않습니다. 영업일·공휴일 달력, 외부 알림 발송과 별도 승인 단계는 추가하지 않았습니다.

## 2. KEV·EPSS 반입과 위험 우선순위

**조사 근거.** Dependency-Track 공식 문서의 EPSS 활용 및 KEV 목록을 영향 프로젝트 API와 연결하는 커뮤니티 예제를 참고했습니다. 이를 모든 제품 버전의 내장 KEV 기능이라고 해석하지 않습니다. [Community Usage Examples](https://docs.dependencytrack.org/usage/community-usage-examples/)

**구현.** 관리자가 KEV JSON과 EPSS CSV를 반입합니다. 본문 32 MiB·최대 500,000개 CVE를 검증하고 기준일·반입일·건수·SHA-256과 형식별 자료를 PostgreSQL에 원자적으로 저장합니다. 외부 피드를 자동 조회하지 않습니다. 중복 CVE·잘못된 숫자·날짜 불일치와 이전 기준일은 거부합니다.

운영 점수 `hunter-priority-v1`은 심각도·서비스 중요도·KEV·유효 EPSS를 합산하고 상한 100점을 적용하며 화면에 근거를 보여줍니다. 누락 EPSS는 실제 0과 구분합니다. 오래된 EPSS는 가산에서 제외하고, 오래된 KEV 포함 사실은 경고와 함께 유지합니다.

**범위.** 점수는 심각도·발견 상태·진단 권한을 바꾸지 않습니다. 침해 확률이나 CVSS가 아니며 경과일 자체를 점수에 더하지 않습니다. SHA-256은 입력 식별값이고 공급자 서명 검증은 아닙니다. 현재 EPSS 입력은 CSV이며 JSON은 API 포장 요청에 사용합니다.

## 3. SBOM 구성요소·버전 비교·라이선스 검토

**조사 근거.** Dependency-Track의 CycloneDX 반입, 구성요소와 조직 라이선스 정책 검토를 참고했습니다. 복합 라이선스 표현식은 단일 식별자와 의미가 다르므로 별도 검토 대상으로 구분합니다. [CycloneDX 반입](https://docs.dependencytrack.org/usage/cicd/), [Policy Compliance](https://docs.dependencytrack.org/usage/policy-compliance/)

**구현.** `/software`에서 CycloneDX 1.4·1.5·1.6 JSON 또는 SPDX 2.2·2.3 JSON을 서비스에 연결합니다. 문서 8 MiB·구성요소 1~10,000개·입력 의존 관계 100,000개 한도로 정규화하고 버전·purl·라이선스·의존 관계를 보존합니다. 같은 서비스의 두 문서에서 추가·제거·변경을 비교하고, 최신 문서의 공통 구성요소와 현재 접근 가능한 영향 서비스를 조회합니다. 기존 발견 건의 정확한 구성요소 식별자 일치를 연결하며 이름·버전이 여러 식별자에 걸쳐 모호하면 연결하지 않습니다. 같은 패키지·버전의 라이선스 변형은 보존하고 `bom-ref`만 바뀐 것은 변경으로 세지 않습니다.

**범위.** 지원 JSON 필드·타입·식별자를 검사하지만 전체 표준 스키마 검증기는 아닙니다. 라이선스는 관리자 검토 목록·미기재·사용자 정의·복합 표현식 등을 검토 대상으로 표시하며 적법성 승인이나 완전한 SPDX 표현식 평가를 하지 않습니다. SBOM 생성, 새로운 취약점 DB 자동 분석, 임의 공급자 파일 보관·실행은 포함하지 않습니다. 구성요소 제거로 발견 건을 자동 해결하지 않습니다.

## 4. 진단 캠페인과 관측 비교

**조사 근거.** ProjectDiscovery의 진단 이력과 발견 건의 탐지·상태 변경 타임라인을 참고했습니다. 다중 대상 캠페인과 보수적 비교 규칙은 Hunter의 자체 설계입니다. [Get Scan History](https://docs.projectdiscovery.io/api-reference/scans/get-scan-history), [Get Vulnerability Timeline](https://docs.projectdiscovery.io/api-reference/results/get-vulnerability-timeline)

**구현.** `/campaigns`에서 최대 20개 서비스·프로파일·시나리오를 묶고 기존 진단 정책과 망별 워커로 실행합니다. 시작은 정책 준비 후 한 트랜잭션에서 전체 진단·큐·승인·연결을 저장하며 동시 재요청에도 한 번만 생성합니다. 모든 대상의 현재 부모 서비스 접근을 검사합니다.

내장 HTTP·권한 진단의 결과를 실행별 불변 스냅샷으로 보존합니다. 양쪽 정상 완료·대상 구성·실행 정책·인증·신뢰 CA·엔진 버전이 같으면 신규·반복·정보 변경·미관측을 비교합니다. 변경은 반복 관측의 부분집합이며 비교 API는 읽기 전용입니다.

**범위.** 외부 `import-only`, 이전 버전, 스냅샷 없는 실행, 실패·취소, 조건 불일치는 비교 불가입니다. **미관측으로 발견 건을 해결하지 않습니다.** 새 실행은 새 캠페인으로 만들고 개별 취소는 연결된 진단에서 처리합니다. 캠페인 대상 수정·캠페인 전체 취소·외부 실행 완전성 판정은 별도 제공하지 않습니다.

## 5. 발견 건 댓글과 활동 이력

**조사 근거.** Faraday의 변경·댓글 피드와 취약점에 연결한 작업 관리 흐름을 참고했습니다. [Activity Dashboard](https://docs.faradaysec.com/Activity-Dashboard/), [Planner](https://docs.faradaysec.com/Planner/)

**구현.** 조치함에서 발견 건의 활동과 댓글을 확인하고 작성합니다. 서버가 작성자·시각을 정하며 댓글은 마스킹 후 암호화합니다. 타임라인은 댓글, 기존 발견 건 저장·위험 수용 만료 감사 사건, 최근 관찰과 현재 재검증 정보를 연결합니다. 담당 변경과 조치 사유는 사람이 댓글에 남깁니다.

**범위.** 모든 필드의 변경 전후 차이를 저장하는 전체 변경 이력은 아닙니다. 관찰은 기존 최근 100개 범위입니다. 메신저·이메일 자동 발송, 댓글 편집·삭제 워크플로, 필수 승인 단계를 추가하지 않았습니다.

## 6. 공통 원인 후보

**조사 근거.** Faraday의 이름·CVE 기반 그룹과 사용자 지정 그룹, 관련 취약점·서비스 탐색을 참고했습니다. [Vulnerability Grouping](https://docs.faradaysec.com/Grouping/)

**구현.** 조치함에서 유효한 같은 CVE와 정확히 같은 구성요소 문자열을 가진 미조치 발견 건이 두 개 이상이면 후보로 묶습니다. 현재 검색과 사용자 접근 범위에서 계산하고 최대 100개 그룹을 표시합니다. 서비스별 증거·기한·상태·재검증은 보존합니다.

**범위.** 후보는 원인 확정·자동 병합이 아닙니다. 별도 수동 그룹 CRUD, 의미 기반 AI 분류, 그룹 일괄 해결은 포함하지 않습니다. 정확한 문자열 일치 밖의 공통 원인은 댓글과 기존 개선 요청에서 검토합니다.

## 7. 관리자 운영 점검

**조사 근거.** Dependency-Track 공식 저장소에서 방화벽과 갱신 작업 로그를 확인해야 했던 EPSS 갱신 운영 사례를 참고했습니다. 특정 현재 버전 전체의 결함으로 일반화하지 않습니다. [EPSS data feed logging? #4776](https://github.com/DependencyTrack/dependency-track/discussions/4776)

**구현.** `/admin/operations`는 DB 응답, 큐 상태·임대 만료, 활성 워커의 응답 지연, 긴급 중지, SSO·AI·에이전트·승인 설정 여부, KEV·EPSS 기준일과 SBOM 갱신을 한 화면에 모읍니다. 추가 필수 서비스나 환경변수 없이 같은 PostgreSQL의 자료를 읽습니다.

**범위.** 외부 대상·OIDC·AI 연결을 실제 호출하지 않습니다. 백업 복구 검증·인증서 만료·외부 가용성·모든 에이전트 실패·연동 불확실 발송을 종합 진단하는 도구는 아닙니다. 외부 발송 상태는 기존 개선 요청 화면에서 확인합니다.

## GitHub에서 확인한 실제 저장소와 설계 교훈

아래 커밋은 조사 시 GitHub API로 확인한 각 공식 저장소 기본 브랜치의 시점 고정값입니다. Hunter에 해당 소스를 새로 가져오거나 실행했다는 의미는 아닙니다.

| 공식 저장소 | 조사 시 커밋 | 참고 범위 |
| --- | --- | --- |
| [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | [254dab83759d](https://github.com/DefectDojo/django-DefectDojo/commit/254dab83759d0d2fd17b5610d7d8413c790c608a) | SLA 모델·재반입 상태 이슈 |
| [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) | [302e6eedf4d7](https://github.com/DependencyTrack/dependency-track/commit/302e6eedf4d7a1e189fdbd6a1528dca24addcb8f) | SBOM·라이선스·EPSS·파일 기반 자료 배포 |
| [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | [a04aba1022ef](https://github.com/projectdiscovery/nuclei/commit/a04aba1022ef6c72e775acb15e5ead886367f07c) | 구조화 결과와 오프라인 파일 연계 |
| [infobyte/faraday](https://github.com/infobyte/faraday) | [17217f446a63](https://github.com/infobyte/faraday/commit/17217f446a639b2d36608b3da37328daf9a14060) | 취약점 협업·그룹·작업 관리 |

| 확인한 이슈·변경 | 원문에서 확인한 사실 | Hunter의 검증 항목 |
| --- | --- | --- |
| [Dependency-Track PR #6274](https://github.com/DependencyTrack/dependency-track/pull/6274) | EPSS가 없는 취약점이 기본 숫자값 때문에 비교 조건에 일치하던 문제를 수정했으며 2026-06-05 병합됨 | 없는 EPSS와 실제 0을 분리하고 `<`, `<=` 비교 회귀 검사 |
| [Dependency-Track Issue #4528](https://github.com/DependencyTrack/dependency-track/issues/4528) | 파일 기반 취약점 DB 배포와 EPSS·KEV 보강을 논의하는 설계 이슈 | 승인된 파일 반입·출처 분리·시점 보존. 제안을 이미 배포된 기능으로 인용하지 않음 |
| [DefectDojo Issue #14363](https://github.com/DefectDojo/django-DefectDojo/issues/14363) | 첫 빈 재반입이 지정하지 않은 테스트의 발견 건을 닫았다는 보고 | 서비스·진단·기준 실행 범위 고정, 빈 결과·실패로 자동 해결 금지 |
| [DefectDojo Issue #14910](https://github.com/DefectDojo/django-DefectDojo/issues/14910) | 중복 발견 건 재활성화 시 모순된 상태가 생긴다는 보고 | 원인 그룹과 발견 건 상태 분리, 재반입·재검증의 상태 일관성 |
| [Nuclei Issue #3504](https://github.com/projectdiscovery/nuclei/issues/3504) | 진행 상황 관찰과 파일 업로드를 위한 JSONL 내보내기 요청, 완료로 종료됨 | 기존 파일 반입을 활용하고 캠페인이 외부 클라우드 업로드를 요구하지 않도록 설계 |

이슈 보고는 해당 환경의 관찰이며 모든 현재 배포에서 재현된다는 뜻은 아닙니다. PR의 병합 여부, 제안과 완료 기능의 차이를 구분했습니다. ProjectDiscovery Cloud 이력 API와 오픈소스 Nuclei를 같은 제품 범위로 혼동하지 않습니다.

## 운영 순서와 유지하는 조건

1. SBOM·위협 정보의 반입 자료와 기준일을 저장하고 영향 서비스·운영 우선순위를 계산합니다.
2. SLA·조치함·댓글·공통 원인 그룹으로 담당자가 실행할 개선 작업을 연결합니다.
3. 캠페인·비교·기존 재검증으로 변경 전후 결과를 확인합니다.
4. 관리자 운영 점검과 가이드에서 미설정·자료 노후화·실패·검증 한계를 명확하게 표시합니다.

서비스 이미지는 하나로 유지하고 PostgreSQL과 기존 네 환경변수를 사용합니다. 신규 관리 정책·자료 반입 설정은 관리자 화면과 API로 관리합니다. 모든 상세·집계·다운로드·비교는 사용자 현재 역할, 팀, 개인 키 범위를 교차 검사해야 합니다. 새 AI 요청도 스트리밍과 기존 실행 권한 경계를 따르며, 점수·그룹·위협 정보가 진단 범위를 확대할 권한은 갖지 않습니다.

현재 제공 범위에는 외부 클라우드 스캐너 번들, 원격 공격 엔진 추가, 자동 PR 병합, 자동 보상 지급, 모든 SPDX 표현식의 법적 판단, 인터넷 실시간 자료 수집, 발견 미관측에 따른 자동 종결을 포함하지 않습니다. 실제 수행한 API·권한·합성 시나리오·오프라인·화면 검증은 검증 기록에 구분해 남깁니다. 가이드와 캡처를 함께 제공하며, 새 읽기 전용 MCP 도구 네 개도 같은 권한 검사를 사용합니다.
