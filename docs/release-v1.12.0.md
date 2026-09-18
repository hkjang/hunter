# Hunter v1.12.0

`/mcp` 를 OAuth 2.1 리소스 서버로 만들어 개인 키와 함께 Keycloak 액세스 토큰도 받는 **MCP · SSO 연결**을 추가한 릴리즈입니다. 기본 꺼짐이며 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- 관리자가 **서비스 설정 → MCP · SSO 연결**(설정 그룹 `mcp` 의 `oauth` 객체, `mcp.oauth.enabled/resource/audience/scopes`)을 켜면 MCP 클라이언트(Claude, Cursor 등)에 `https://hunter.internal/mcp` 주소 하나만 넣어도 클라이언트가 스스로 Keycloak 로그인 창을 띄우고 액세스 토큰을 받아 옵니다. 개인 키 페이지의 MCP 카드에 "키 없이 SSO 로 연결하기" 안내가 보이며(`/api/settings/public` 의 `mcp_sso_enabled`·`mcp_sso_url`), 키가 필요한 자동화 스크립트는 지금처럼 개인 키를 씁니다.
- Hunter 는 **리소스 서버**입니다. 토큰을 발급하지 않고(`/authorize`·`/token`·동적 클라이언트 등록 없음) `/.well-known/oauth-protected-resource(/mcp)` 메타데이터(RFC 9728, 맨 JSON, CORS `*`, 꺼지면 404)와 `/mcp` 401 의 `WWW-Authenticate: Bearer realm="hunter", resource_metadata="…"` 헤더로 클라이언트를 Keycloak 으로 보냅니다. 이 헤더는 MCP 경로에만 붙고 REST·GraphQL·관리 API 는 지금처럼 키·세션만 받습니다. 리소스 식별자는 `mcp.oauth.resource`, 비우면 서비스 외부 접근 주소 + `/mcp` 이며 요청 `Host` 헤더는 쓰지 않습니다.
- 같은 `Authorization: Bearer` 헤더에서 `hnt_` 접두사는 키, JWT 모양은 SSO 토큰으로 가릅니다. 토큰은 헤더 `typ=ID`·비대칭 알고리즘(RS/ES/PS)만 허용을 JWKS 요청 전에 먼저 보고, 서명·`iss`·`exp`·`nbf` 와 `cnf`·`sub`·대상(`aud` 에 리소스 식별자, 또는 `aud`/`azp` 가 허용 대상 목록 또는 웹 로그인 Client ID)을 검사합니다. 계정은 웹 로그인과 같은 `digest(issuer|sub)` 로 **이미 웹 로그인한 활성 계정**만 찾고, 사용자명 대체 조회·계정 생성·토큰 role 승격은 없습니다. 권한은 `mcp.oauth.scopes`(기본 읽기 3개) ∩ 역할 권한이며 교집합이 비면 거부합니다.
- 켤 때 OIDC 가 꺼져 있거나 Issuer 가 없거나 범위가 비면 저장을 400 으로 거부하고, 켠 뒤 전제가 사라지면 조용히 꺼진 것처럼 동작하며 `mcp oauth switched on but inactive` 로그를 남깁니다. 거부는 401 본문의 한국어 메시지(다른 대상이면 본 `aud`/`azp` 와 적을 값을 함께)와 서버 로그 `mcp sso token rejected cause=…` 로 남기고, SSO 토큰으로 호출한 도구는 감사 기록 `mcp.<도구>` 에 `auth: sso` 로 표시됩니다.

## 운영 조건과 한계

Keycloak 쪽에는 MCP 클라이언트용 공개 클라이언트(PKCE S256, 정확한 Redirect URI)와 리소스 식별자 Audience 매퍼(정식 경로) 또는 Hunter 허용 대상에 클라이언트 ID 등록(호환 경로)이 필요합니다. Hunter 는 introspection 을 하지 않으므로 Keycloak 로그아웃·사용자 비활성화 뒤에도 이미 발급된 토큰은 만료까지 살며, 급하면 Hunter 사용자를 비활성화합니다(비활성 계정 토큰은 즉시 거부). 실제 Keycloak·실제 MCP 클라이언트로 URL 만 넣어 연결하는 것은 이 환경에 Keycloak 이 없어 가짜 IdP 가 서명한 Keycloak 26 모양 토큰으로 대체 검증했습니다.

## 검증과 배포

Go 테스트로 기본 꺼짐·메타데이터 404·꺼진 상태의 토큰 거부(JWKS 미요청)·OIDC 없이 켜기 400, 설정 검증 6가지 거절과 정규화, 가짜 IdP 가 서명한 JWT 로 메타데이터·MCP 전용 401 헤더·매퍼 경로 통과·감사 `auth: sso`·다른 대상 거부 메시지·azp 허용 목록·웹 client_id·만료·nbf·다른 issuer·typ=ID·cnf·sub 없음·미등록·HS256(키 요청 없이)·비활성 계정·빈 교집합 거부·REST/GraphQL 에서 토큰 거부·키 그대로 동작·공개 설정·끄면 즉시 닫힘, 사용자 지정 리소스를 추가했습니다. 릴리즈 커밋에서 `go vet`, 임시 PostgreSQL 컨테이너의 `go test -race`, `npm test`, `npm run build`(tsc 포함), `node scripts/render-guides.mjs`, `node scripts/check-docs.mjs`, `bash -n scripts/release.sh`, `python3 -m py_compile scripts/release-notes.py`를 실행했습니다. 최종 게시 커밋의 CI와 공개 아카이브 다운로드 검증은 실제 완료한 뒤 [릴리즈 본문](https://github.com/hkjang/hunter/releases/tag/v1.12.0)에 기록합니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 관리자 가이드 §15.6·설정 그룹 표·사용자 가이드 §12.4·README·llms.txt·AGENTS.md·openapi.json(경로 2개·스키마 1개·settings enum)을 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.12.0` · 유일한 첨부 자산: `hunter-v1.12.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [공식 조사와 적용 범위](research-sso-tracking.md) · [v1.11.0 릴리즈 노트](release-v1.11.0.md)
