# v1.8 에이전트 연동·복구와 조회 API의 공식 근거

조사·구현 대조일: 2026-09-13. 이 문서는 공식 프로토콜을 참고해 작성한 Hunter 어댑터의 실제 범위를 설명합니다. PentAGI 원본 312파일은 같은 고정 커밋을 보존하며 새 기능은 Hunter 코드에 구현했습니다. 기능별 실제 시험과 배포 검증은 [검증 기록](validation.md)에 구분합니다.

## 1. 원본 코어와 선택 연동

기존 원본 계획·위임·수행·성찰·요약 경로를 유지합니다. 관리자 선택 연동이 꺼져 있어도 같은 네 환경변수와 일반 PostgreSQL로 기본 서비스를 시작합니다. 검색·메모리·관측 장애는 내부 자료 또는 비동기 처리로 분리하고, 모델이 모두 불가하면 실행 근거를 보존한 연결 대기에서 명시적으로 재개합니다. 원본 Compose의 여러 서버를 서비스 이미지에 묶거나 자동 기동하지 않습니다.

### 모델의 네 가지 실제 전송 규격

| 공식 근거 | Hunter 적용 | 제한과 실패 처리 |
| --- | --- | --- |
| [OpenAI Chat API](https://developers.openai.com/api/reference/resources/chat) | `/chat/completions` 스트리밍, 메시지·도구 인자 조각·usage | OpenAI 호환 사내 서버에도 사용. 모든 공급자 고유 기능을 동일하게 지원한다는 의미는 아님 |
| [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming) | Messages 이벤트, text·input JSON delta와 usage를 공통 응답으로 변환 | 완료되지 않은 content block과 잘못된 도구 인자는 커밋하지 않음 |
| [Gemini generateContent](https://ai.google.dev/api/generate-content), [function calling](https://ai.google.dev/gemini-api/docs/function-calling) | streamGenerateContent SSE, parts·functionCall·usage 변환. 필요한 thoughtSignature는 실행·호출·공급자 identity별 암호화 보존 | 다른 공급자에게 signature를 전달하지 않음. 원본 코어 파일 변경 없음 |
| [Ollama Chat API](https://docs.ollama.com/api/chat) | native `/api/chat` NDJSON, done·도구 호출·평가 토큰 수 변환 | OpenAI 호환 주소만 사용하는 어댑터와 구분 |

공급자 최대 20개, 역할별 지정 순서 또는 우선순위를 적용합니다. 요청은 실제 스트리밍 프로토콜로 읽지만 사용자 출력과 도구는 답변 완료·검증 뒤 커밋합니다. 실패 제공자의 부분 답변을 다음 제공자의 답변과 연결하지 않습니다. 긴 한국어도 UTF-8 경계를 지켜 분할합니다. 이 방식은 첫 사용자 출력까지 기다리는 시간이 길어질 수 있습니다.

컨텍스트·출력 설정은 최대 262,144까지 다루며 실제 공급자와 실행 제한 중 작은 값을 적용합니다. 직렬화 입력 바이트 기반 사전 검사는 정확한 토크나이저 계산이 아닙니다. 실행의 usage 합계는 성공한 제공자 응답을 기준으로 하며 실패한 요청의 정확한 과금 합계로 사용하지 않습니다.

## 2. 검색과 로컬 원본 메모리

검색 어댑터는 [Tavily Search](https://docs.tavily.com/documentation/api-reference/endpoint/search), [Perplexity Search](https://docs.perplexity.ai/api-reference/search-post), [SearXNG Search API](https://docs.searxng.org/dev/search_api), [Google Custom Search](https://developers.google.com/custom-search/v1/using_rest), DuckDuckGo Instant Answer와 필드 매핑형 사내 HTTP JSON을 지원합니다. DuckDuckGo는 요약 응답이며 일반 웹 검색 전체와 동일하지 않습니다. 최대 8개 공급자를 순차 시도하고 결과는 최대 10개입니다.

검색어는 선택 서버로 전송될 수 있습니다. 결과는 제목·URL·짧은 본문이 있는 비신뢰 참고 자료로 표시하며 실행 지시·새 대상 승인으로 사용하지 않습니다. 검색 불가는 내부 서비스·발견 건·기억을 사용하는 분석과 구분합니다.

[OpenAI embeddings 규격](https://developers.openai.com/api/reference/resources/embeddings/methods/create)을 사용하는 임베딩 연결과 [Graphiti REST 구현](https://github.com/getzep/graphiti/tree/main/server/graph_service)을 지원합니다. Graphiti `/messages`의 비동기 접수와 `/search` 결과를 연결하되 원격 fact 문장은 반환하지 않습니다. 현재 허용된 로컬 메모리 ID·내용 해시로 확인한 본문만 사용합니다. 연결 시험도 합성 그룹의 검색 응답 검사이며 비동기 인덱싱 완료 시험은 아닙니다.

사용자·서비스별 로컬 100개 메모리와 벡터는 암호화합니다. [pgvector](https://github.com/pgvector/pgvector)가 이미 설치되어 있으면 스키마를 확인한 매개변수 쿼리를 사용하고, 없으면 Go cosine·키워드로 대체합니다. 확장을 자동 설치하거나 평문 벡터를 영구 테이블에 저장하지 않습니다. 예전 기억의 일괄 원격 업로드, 원격 Graphiti의 과거 episode 자동 삭제는 제공하지 않으며 관리자 외부 보존 정책이 필요합니다.

## 3. 고정 격리 진단과 같은 실행 재개

[Docker 공식 TLS 접근 문서](https://docs.docker.com/engine/security/protect-access/)의 인증된 원격 API를 사용합니다. 관리자가 사내 mTLS 주소·CA·클라이언트 인증서·암호화 비밀키·망과 고정 이미지 digest를 등록합니다. 기존 서비스 이미지의 고정 프로브로 승인된 IP의 HTTP HEAD·TLS 인증서·TCP 연결을 각각 제한 수행합니다. 서비스 망과 실행 서버의 service_network가 정확히 일치해야 합니다. Docker 네트워크 이름 network는 별도 ASCII 값입니다.

컨테이너는 비특권 사용자, 읽기 전용 루트, 권한 제거와 메모리·CPU·PID·시간 상한을 사용합니다. 로컬 호스트 소켓·볼륨 마운트·임의 셸·공격 모듈 실행·자동 이미지 pull을 제공하지 않습니다. 별도 Docker daemon은 선택 기능의 사내 인프라로 준비하며 릴리즈에 두 번째 실행 이미지를 첨부하지 않습니다. Docker 인증 자격의 권한은 조직이 daemon 측에서도 통제합니다.

생성 전 실패는 다른 서버를 시도할 수 있지만 생성 이후 불명 상태는 같은 서버와 컨테이너 이름으로 확인합니다. 불명확한 실제 행위를 다른 서버에서 다시 실행하지 않습니다. 일반 자산과 내장 진단은 이 선택 기능의 실패와 분리됩니다.

`pause`, `input`, `resume`은 원래 실행자의 현재 키·역할·서비스·범위·정책을 재검사합니다. 입력과 도구 영수증을 암호화하고 체크포인트를 명시 재개합니다. 모델·Hunter 도구 호출과 활성 시간은 누적하며 원본 역할 체인 반복은 호출마다 적용합니다. 종료된 실행·일반 프로세스 강제 종료에 대한 무조건 자동 재실행은 없습니다.

## 4. 비동기 메타데이터 관측

[OTLP 공식 규격](https://opentelemetry.io/docs/specs/otlp/)의 HTTP JSON traces·metrics·logs와 [Langfuse 공식 OpenTelemetry 연동](https://langfuse.com/integrations/native/opentelemetry)을 사용합니다. Langfuse는 public/secret Basic 인증과 `/api/public/otel/v1/traces`를 사용합니다. 오래된 독자 ingestion API를 신규 연결 규격으로 사용하지 않습니다.

Hunter가 내보내는 것은 안전한 식별자·성공 상태·호출 수·토큰 수·소요 시간 같은 메타데이터입니다. 프롬프트·도구 인자·결과·증거·인증정보를 내보내는 전체 로그 수집이 아닙니다. Jaeger·VictoriaMetrics·Loki는 조직의 OpenTelemetry Collector에서 라우팅하며 해당 제품 스택을 번들하지 않습니다.

암호화 outbox는 최대 10,000개, 재시도 1~10회, 보존 1~90일입니다. 큐 기록 실패·포화가 업무 응답을 중단하지 않으며 같은 대체 그룹 내에서만 수집기를 순차 시도합니다. 부분 접수는 재전송하지 않고 설정 변경 전 자료는 폐기합니다. 수집 응답 유실 뒤 메타데이터 중복 가능성은 있으므로 정확히 한 번 전달로 설명하지 않습니다.

## 5. GraphQL과 한국어 실행 보고서

공식 [gqlparser](https://github.com/vektah/gqlparser)의 파서·검증기를 고정 의존성으로 사용합니다. 인증된 query만 허용하며 service/finding/scan/agent run 목록·단건의 선택 필드를 조회합니다. 각 resolver와 응답 직전 현재 사용자·키·부모 서비스 권한을 검사합니다. introspection과 SDL도 인증되며 query 깊이·필드·복잡도·페이지·시간을 제한합니다. mutation·subscription·JSON batch·임의 자원 JSON은 제공하지 않습니다.

보고서 생성은 [gopdf](https://github.com/signintech/gopdf)의 Go PDF 기능과 [고정 NanumGothic OFL](https://github.com/google/fonts/blob/133ccbee9a8b408eb71f31a36ccb9116f5c695ad/ofl/nanumgothic/OFL.txt)을 사용합니다. 파일은 실행 바이너리에 포함해 인터넷·외부 PDF 프로세스 없이 생성합니다. MD·HTML·PDF에는 현재 진행·대기·실패를 사실대로 표시하고 마스킹과 한도·잘림 안내를 적용합니다. HTML은 escape와 CSP를 적용합니다. 다운로드가 취약점 확인·해결 증명서를 자동 발급하는 것은 아닙니다.

## 6. 검증의 의미

프로토콜·실패·권한·409·중복 방지·재개 검증은 격리 PostgreSQL과 사내 모의 HTTP/SSE/NDJSON 서버를 사용합니다. 한국어 PDF는 별도 텍스트 추출기로 확인합니다. 실제 공급자 계정·검색 결과 품질·모델 판단 정확도·외부 운영 daemon의 모든 구성·실제 취약점 탐지율을 보장하는 시험은 아닙니다. 최종 이미지의 오프라인 실행과 공개 배포 파일 검증은 완료된 결과만 [검증 기록](validation.md)에 추가합니다.
