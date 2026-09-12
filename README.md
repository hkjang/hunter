# hunter

**사내 서비스의 발견 → 검증 → 개선 → 재검증을 연결하는 보안 검증 플랫폼.**

Go + React + Mantine + PostgreSQL로 만들었으며 서비스 서버·화면·한국어 폰트를 한 Docker 이미지에 담아 폐쇄망에 배포합니다. 기본 UI는 한국어입니다.

[제품 소개](https://hkjang.github.io/hunter/) · [릴리즈](https://github.com/hkjang/hunter/releases) · [사용자 가이드](docs/guides/user-guide.md) · [관리자 가이드](docs/guides/admin-guide.md) · [전체 화면](https://hkjang.github.io/hunter/screenshots.html)

![Hunter 보안 현황](docs/images/dashboard.png)

## 제공 기능

- 서비스 자산, 망·환경·담당자·중요도, 공격 표면과 관계 그래프
- 승인된 범위의 실제 HTTP 보안 헤더 진단, 합성 데이터 기반 업무 권한 비교
- 발견 건·증거·중복 관찰·개선·재검증 관리, 설정한 ITSM·개발 API로 개선 초안 발송
- 조치함·SLA 기한·KEV/EPSS 오프라인 반입과 근거가 있는 운영 우선순위
- CycloneDX·SPDX SBOM 반입, 구성요소·영향 서비스·버전 비교와 라이선스 검토 표시
- 서비스별 발견 건을 유지하는 공통 원인 후보, 암호화 댓글과 협업 이력
- 여러 진단을 묶는 캠페인, 동일 조건의 내장 완료 실행 비교, 관리자 운영 점검
- 5분~7일 간격의 진단 예약과 같은 이미지를 사용하는 망별 워커 전용 실행
- Trivy, Nuclei, ZAP, SARIF, Gitleaks와 일반 JSON 결과 가져오기
- REST·읽기 전용 PostgreSQL 자산 수집, 변경 이벤트 웹훅, 정책을 따르는 재진단
- Keycloak OIDC discovery, 관리자·개인화 분리, 변경 가능한 역할 권한
- 개인 API 키 발급·권한 수정·원자적 회전·폐기, REST API와 HTTP MCP
- OpenAI 호환 사내 AI, 기본 SSE 스트리밍, 최대 262,144 컨텍스트·출력 설정
- PentAGI MIT 코어 기반 에이전트 진단: 계획·위임·실행·재시도·성찰·요약, Hunter 도구와 현재 권한 안에서 수행
- 선택적 팀장 검토·승인, 감사 기록, 긴급 중지, JSON·CSV 보고서
- 관리자 알림센터: SMTP·문자·카카오톡·HTTP 채널, 이벤트 규칙·템플릿, 암호화 대기열·전달 이력
- 발견 건 최대 100개 담당자·기한·진행 상태 일괄 변경, 현재 권한·조회 버전 검사와 전체 롤백
- 현재 목록 CSV·주소와 상세 식별자 복사, 일반 자원 편집 충돌 안내·작성 중 입력 보호
- 로그인 화면과 프로필 메뉴의 버전, 모바일 탐색, 새로고침 경로 유지
- 주요 목록의 한국어 검색·열 정렬·복합 필터·페이지 이동, URL로 목록 조건 보존
- Ctrl+K/⌘K 빠른 이동, 한영 별칭·초성 검색, 사용자별 즐겨찾기·최근 방문

UI는 Mantine을 사용합니다. 접근 가능한 폼·대화상자·표·메뉴를 일관되게 구성하고, 한국어 폰트를 로컬 번들하여 폐쇄망에서도 읽기 편한 화면을 제공합니다.

v1.7.0은 **자동화 관리**와 **내 업무 알림**을 추가합니다. 담당자·서비스 소유자·조직·당직 수신자, 알림 묶음·한도, 영업일 기한 예고, 업무 확인·미확인 알림, 주간 요약, 공급자 결과 조회·실패 확정 시 대체 채널, 변경 영향별 진단 선택, ITSM 상태 동기화, 비발송 모의 검사, 보존 기간별 본문 파기를 관리자가 필요한 범위만 켭니다. 새 자동화는 기본 비활성이며 기존 고정 수신자 규칙은 유지됩니다.

**게이트웨이 접수·공급자 전달 결과·사용자 업무 확인·팀장 승인은 서로 다른 상태입니다.** 불명확한 전달을 자동 재발송하지 않으며 외부 티켓 완료만으로 발견 건을 해결하지 않습니다. 서명 콜백은 Hunter 게이트웨이 규격으로, 공급자나 Git 서비스의 원래 콜백을 그대로 받는 범용 연결은 아닙니다. [공식 설계 근거와 실제 범위](docs/research-automation.md), [상세 운영 절차](docs/guides/admin-guide.md#1310-자동화-관리-시작하기)를 참고하세요.

발견 건 일괄 변경, CSV·주소 복사, 편집 충돌 안내, 입력 보호, 탭별 저장 보기와 새 캠페인 초안도 함께 제공합니다. [기존 운영 기능 조사](docs/research-v140.md)는 공식 프로젝트 문서·GitHub 이슈에 근거하며, 알림과 운영 기능은 Hunter 자체 코드입니다. 기존 PentAGI 원본 코어는 그대로 보존합니다.

캠페인 비교의 **미관측은 해결을 뜻하지 않습니다**. 신뢰할 실행 조건이 없는 외부 반입·이전 버전 결과는 비교하지 않습니다. EPSS 정보 없음은 0과 다르며, SBOM 라이선스 표시는 조직의 검토 규칙에 따른 것으로 법적 적합성 판정이 아닙니다.

## 오프라인 설치

PostgreSQL은 조직의 사내 서비스를 별도로 준비합니다. 릴리즈 첨부 자산은 **Hunter 서비스 이미지 하나**이며 PostgreSQL·외부 진단 엔진·문서 압축 파일을 함께 첨부하지 않습니다.

알림을 사용하려면 사내 SMTP 릴레이 또는 조직이 허용한 문자·알림톡 API 경로가 필요합니다. 별도 환경변수나 필수 메시지 브로커는 추가하지 않습니다. 외부 통신이 차단된 망에서는 승인된 사내 중계 서비스를 통해 연결합니다.

~~~sh
docker load -i hunter-v1.7.0.tar.gz
cp .env.example .env
chmod 600 .env
openssl rand -base64 32
~~~

`.env`에 아래 네 값만 실제 정보로 설정합니다.

~~~dotenv
POSTGRES_DSN=postgres://hunter:URL_ENCODED_PASSWORD@postgres.internal:5432/hunter?sslmode=verify-full
BOOTSTRAP_ADMIN=admin
BOOTSTRAP_ADMIN_PASSWORD=A_UNIQUE_PASSWORD_AT_LEAST_12_CHARACTERS
ENCRYPTION_KEY=BASE64_ENCODED_32_RANDOM_BYTES
~~~

~~~sh
docker compose up -d
curl --fail http://localhost:8080/api/health
~~~

기본 포트는 8080입니다. 초기 관리자로 로그인한 뒤 **관리자 → 서비스 설정**에서 서비스 공개 주소, 사내 인증서, OIDC, AI, 세션과 역할 권한을 설정합니다. 초기 관리자는 사용자가 없는 DB에만 생성되며, 암호화 키는 기존 DB와 반드시 동일하게 유지해야 합니다.

**키를 재생성하지 마세요.** DB와 원래 `ENCRYPTION_KEY`를 함께 복구할 수 있도록 안전하게 보관하세요. 운영 설치, HTTPS, 백업·복구와 업그레이드는 [관리자 가이드](docs/guides/admin-guide.md)에 설명되어 있습니다.

## 인증과 연동

Keycloak에는 `https://hunter.internal/api/auth/oidc/callback`을 redirect URI로 등록합니다. Hunter 관리자 화면에 realm issuer, client ID, client secret을 저장하면 discovery로 연결합니다. 플랫폼 SSO와 진단 대상 테스트 계정은 별도 인증 프로파일로 관리합니다.

개인 키는 **개인화 → 개인 API 키**에서 발급합니다. 키의 실제 권한은 소유자의 현재 역할 권한과 키에 설정한 범위의 교집합입니다.

~~~sh
curl 'https://hunter.internal/api/services' \
  -H 'Authorization: Bearer YOUR_HUNTER_KEY'
~~~

- OpenAPI: `/api/openapi.json`
- MCP: `POST /mcp`, 개인 Bearer 키 인증
- 도구: 기존 서비스·발견 조회와 진단 요청에 더해 `hunter_finding_queue`, `hunter_list_components`, `hunter_list_campaigns`, `hunter_compare_campaigns`를 제공합니다. [관리자 가이드의 MCP 권한 표](docs/guides/admin-guide.md#153-mcp-연결)를 참고하세요.
- AI: `POST /api/ai/chat`, SSE 스트리밍

MCP는 API 키를 지원하는 HTTP 클라이언트에서 사용하며 OAuth 동적 등록을 제공하지 않습니다. AI 최대 설정은 연결한 실제 모델의 지원 한도에 따라 조정합니다.

## 진단 범위

진단에는 **명시적으로 승인한 서비스와 유효한 범위**가 필요합니다. 팀장 승인 기능은 관리자 설정으로 켜거나 끌 수 있으며, 이 기능을 꺼도 대상 승인·정책 검사는 유지됩니다.

서비스의 HTTP 진단은 제한된 헤더 점검과 정의한 읽기 전용 권한 시나리오입니다. Nuclei·Trivy·ZAP·Semgrep·Gitleaks 바이너리와 취약점 DB를 번들하지 않습니다. 외부 도구는 조직이 승인한 실행 환경에서 운영하고 JSON 결과를 수입합니다.

전체 소스 자동 수정·병합, 범용 공격 실행, 자동 보상 지급 등은 제공 범위에 포함하지 않습니다. 구체적인 제공·확장 범위는 [관리자 가이드](docs/guides/admin-guide.md)의 첫 장에서 확인하세요.

기존 일반 목록·보고서·대시보드·관계 그래프는 접근 가능한 자료를 종류별 생성 시각 기준 최신 5,000건까지 조회·집계합니다. 에이전트 목록과 감사 기록은 최신 1,000건까지 조회합니다. 목록의 검색·정렬·페이지 이동은 이 조회 자료 안에서 작동하며, 한도에 도달하면 화면에 검색 범위를 표시합니다. 이 한도를 넘는 기존 일반 목록의 전체 이력 집계와 서버 페이지 조회는 후속 확장이 필요합니다. v1.4 조치함은 예외로, 전체 접근 범위의 검색·집계·페이지를 서버에서 처리합니다. SBOM·캠페인도 별도 저장소와 조회 경로를 사용합니다.

## 목록과 빠른 이동

열 제목을 눌러 오름차순·내림차순을 전환합니다. 이름의 숫자는 자연 순서로, 심각도는 위험 등급순으로 정렬합니다. 검색창에서 `결제 심각`처럼 여러 단어를 입력하거나 상태·환경·서비스 필터를 함께 적용하고, 하단에서 표시 수와 페이지를 바꿉니다. 검색 조건은 주소에 보존되어 새로고침·뒤로 가기·로그인 후에도 유지됩니다. 상세 패널의 이전·다음 항목으로 현재 목록을 연속 검토할 수 있습니다.

상단 **빠른 이동** 또는 **Ctrl+K / ⌘K**를 열어 메뉴명, `scan` 같은 별칭, `ㅂㅇㅎㅎ` 같은 초성으로 검색합니다. **↑/↓ → Enter**로 이동하고 **Esc**로 닫습니다. 별표로 저장한 즐겨찾기와 최근 방문은 같은 브라우저의 사용자별 공간에 보관하며 현재 접근 가능한 메뉴만 표시합니다.

목록 위에서 결과 수와 적용 조건을 확인하고 조건을 하나씩 해제합니다. **저장한 보기**에 현재 검색·필터·정렬·표시 수를 사용자·메뉴별로 최대 8개 보관하며, 불러오면 첫 페이지에서 시작합니다. 이 설정은 해당 브라우저에만 저장합니다. **표 표시 설정**에서 글자 크기를 유지한 채 행 여백을 줄이거나 표 전체를 펼칠 수 있습니다. 기본 보기에서는 열 제목과 데스크톱 첫 열을 고정하며, 모바일 첫 열과 전체를 펼친 표의 열 제목은 고정하지 않습니다.

SBOM·캠페인 상세의 탭은 검색·정렬·페이지와 비교 기준을 따로 기억하고, SBOM의 서비스 필터도 저장한 보기에서 복원합니다. 캠페인의 **같은 대상으로 새 캠페인**은 현재 접근 권한을 재확인한 뒤 검토용 새 초안을 만들며 진단은 별도로 시작합니다.

관리자 설정·개인화의 입력 오류는 해당 필드로 이동할 수 있으며, 저장 실패는 입력을 유지한 안내로 표시합니다. 설정 탭을 바꿀 때 저장하거나 작성 내용을 유지할 수 있으며, 다른 설정 그룹을 저장해도 작성 중인 내용을 덮어쓰지 않습니다. 키보드의 본문 바로가기와 모바일 메뉴의 초점 이동도 지원합니다. [UX 조사 근거와 검증 범위](docs/ux-research.md)를 함께 공개합니다.

## 에이전트 진단

1.1.0의 **에이전트 진단**은 PentAGI의 고정 커밋에서 가져온 계획·위임·실행·재시도·성찰·대화 요약 코어를 사용합니다. 관리자 설정에서 기능을 켜고 사내 AI 연결을 구성하면 서비스별 작업을 요청하고, 상세 화면에서 작업·도구 호출·실시간 진행과 중지 상태를 확인합니다. 실패한 실행은 새 실행으로 다시 시도합니다.

기본값은 비활성화이며 실제 진단 요청도 별도 허용이 필요합니다. 에이전트에는 서비스 조회, 발견 건 조회, 진단 요청·결과 조회, 후보 등록, 기억 저장·검색의 일곱 Hunter 도구만 연결합니다. 일반 PostgreSQL과 기존 네 환경변수·서비스 이미지 하나를 사용하며, 원본 Docker 실행기·클라우드 검색·원격 텔레메트리를 초기화하지 않습니다.

[코어 출처와 라이선스·통합 경계](docs/architecture/pentagi-integration.md)에 원본 커밋, 보존한 고지와 구현의 연결 범위를 기록합니다. 최종 이미지의 라이선스 자료는 `/usr/share/licenses/hunter/`에 포함합니다.

## 개발

Go 1.26, Node.js 26, PostgreSQL을 준비합니다. 빌드 구간에는 의존성 다운로드가 필요하며 완성된 서비스 이미지의 런타임에는 인터넷 접속이 필요하지 않습니다.

~~~sh
npm --prefix web ci
npm --prefix web run build
mkdir -p internal/webassets/dist
cp -a web/dist/. internal/webassets/dist/
go test ./...
go build ./cmd/hunter
~~~

DB 통합 테스트는 테스트 전용 PostgreSQL DSN을 `HUNTER_TEST_DSN`으로 지정한 테스트 프로세스에서 실행합니다. 이 변수는 운영 서비스 환경변수가 아닙니다. 운영 DB를 테스트에 사용하지 않습니다.

~~~sh
HUNTER_TEST_DSN='postgres://hunter:password@localhost:5432/hunter_test?sslmode=disable' go test -race ./...
~~~

## 가이드와 실제 화면

| 가이드 | Markdown | HTML | PDF |
| --- | --- | --- | --- |
| 사용자 | [읽기](docs/guides/user-guide.md) | [보기](https://hkjang.github.io/hunter/guides/user-guide.html) | [다운로드](docs/guides/user-guide.pdf) |
| 관리자 | [읽기](docs/guides/admin-guide.md) | [보기](https://hkjang.github.io/hunter/guides/admin-guide.html) | [다운로드](docs/guides/admin-guide.pdf) |

실제 앱에서 캡처한 모든 화면은 `docs/images`와 [제품 화면 갤러리](https://hkjang.github.io/hunter/screenshots.html)에 있습니다. 문서용 예시 데이터는 운영 시작 시 자동 등록되지 않습니다.

~~~sh
npm --prefix docs ci
npm --prefix docs exec -- playwright install chromium
node scripts/sync-doc-assets.mjs
node scripts/render-guides.mjs
node scripts/check-docs.mjs
~~~

## 릴리즈

버전은 `VERSION`에서 관리합니다. 이미지 태그와 압축 파일은 다음 형식을 따릅니다.

| 항목 | 형식 | v1.7.0 예시 |
| --- | --- | --- |
| Docker 이미지 | hunter:v버전 | hunter:v1.7.0 |
| 유일한 첨부 자산 | hunter-v버전.tar.gz | hunter-v1.7.0.tar.gz |

~~~sh
bash scripts/release.sh 1.7.0
~~~

GitHub Actions는 버전 태그에서 서비스 이미지를 빌드하고 `docker save | gzip` 압축 파일만 릴리즈에 첨부합니다. SHA-256은 릴리즈 본문에 기록합니다. GitHub가 자동 표시하는 소스 코드 다운로드는 별개입니다.

홍보 페이지와 가이드는 `docs` 아래에 있으며 GitHub Pages로 별도 배포합니다. 정적 HTML, 로컬 자산, 검색 메타데이터, FAQ 구조화 데이터, sitemap과 llms.txt를 포함합니다.

## 보안과 라이선스

범위가 명시된 독립 재현 결과와 재실행 소스는 [보안 회귀 검증 기록](docs/security-review.md)에서 확인할 수 있습니다.

취약점 제보와 운영 통제는 [SECURITY.md](SECURITY.md)를 참고하세요. 소스는 [MIT License](LICENSE)로 제공합니다.
