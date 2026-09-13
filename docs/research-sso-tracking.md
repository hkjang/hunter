# 기존 SSO 세션 자동 진입과 방문 추적의 적용 범위

조사일: 2026-09-13 · Hunter v1.9.0

이번 변경은 기존 인증·권한 검사를 유지하면서 사내 인증 세션의 자동 확인과 관리자 선택 방문 통계를 제공합니다. 기능의 동작 조건과 외부 시스템에서 확인할 사항을 구분합니다. 실제 검증 환경·결과는 [검증 기록](validation.md), 설정 절차는 [관리자 가이드](guides/admin-guide.html)에서 확인합니다.

## OIDC와 Keycloak의 공식 근거

OIDC `prompt=none`은 로그인·동의 화면 같은 사용자 조작 없이 인증 결과를 요청합니다. 인증 또는 추가 조작이 필요하면 공급자가 `login_required`, `interaction_required`, `consent_required`, `account_selection_required` 등의 오류를 반환할 수 있습니다. 따라서 자동 확인 실패를 반복 로그인으로 연결하지 않고 명시 로그인 선택으로 복구합니다. 기존 Authorization Code·state·nonce·PKCE와 서명된 ID token 검증은 계속 적용합니다. [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)

Discovery의 issuer는 설정 및 ID token의 issuer와 정확히 일치해야 하며, authorization endpoint·token endpoint·JWKS에는 해당 제공자의 유효한 주소가 필요합니다. 사용자는 issuer·client ID·client secret과 정확한 callback 주소를 설정하되, 제공자별 지원 규격도 확인합니다. [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)

Keycloak의 브라우저 어댑터 문서는 `check-sso`와 숨은 iframe 방식의 `silent check-sso`, 브라우저 추적 방지·타사 쿠키 제한에 따른 차이를 설명합니다. Hunter는 서버가 최상위 브라우저 이동으로 `prompt=none`을 요청하며 숨은 IdP iframe의 타사 쿠키에 의존하지 않습니다. 이것이 모든 브라우저·망·IdP 세션에서 성공을 보장한다는 뜻은 아닙니다. [Keycloak JavaScript adapter](https://www.keycloak.org/securing-apps/javascript-adapter)

## ReSSO 공식 저장소와 소스 대조

[공개 ReSSO 저장소](https://github.com/hkjang/ReSSO)는 Go·React 기반 Keycloak 호환 OIDC 서비스입니다. 조사 기준 커밋은 `f508c7901ad4d0a5437aa87be12710fa1fa37192`이며, 현재 구현을 고정해 아래 계약을 대조했습니다. [ReSSO README](https://github.com/hkjang/ReSSO/blob/f508c7901ad4d0a5437aa87be12710fa1fa37192/README.md)

| 원본에서 확인한 계약 | Hunter 적용 |
| --- | --- |
| Realm issuer와 Keycloak 형태의 Discovery·authorization·token·JWKS 주소 | 실제 Realm issuer를 관리자 OIDC 설정에 입력 |
| query 응답, Code, PKCE S256, RS256 ID token | Hunter의 Code·PKCE·서명 검증 흐름 유지 |
| token endpoint의 client_secret_basic/client_secret_post | 등록한 confidential client ID·secret 사용 |
| 현재 realm의 SSO 세션 재사용, prompt=none에서 세션 없음은 login_required | 기존 인증 세션으로 자동 진입, 인증 필요 시 명시 로그인 복구 |
| 성공·오류 응답의 RFC9207 iss, discovery와 동일한 issuer 원문 | 현재 설정한 issuer와 callback·token issuer 검사 |

해당 동작은 [ReSSO OIDC 소스](https://github.com/hkjang/ReSSO/blob/f508c7901ad4d0a5437aa87be12710fa1fa37192/internal/httpserver/oidc.go)에서 확인했습니다. 세션 조회의 DB 오류는 세션 없음과 구분해 server_error로 반환합니다. [공식 호환 문서](https://github.com/hkjang/ReSSO/blob/f508c7901ad4d0a5437aa87be12710fa1fa37192/docs/compatibility.md)도 promptnone·issuer·서명 규격과 제한을 설명합니다.

ReSSO 관리자는 외부에서 접근하는 HTTPS Realm 주소와 Hunter callback을 정확히 등록하고 client secret을 준비합니다. Hunter의 issuer는 후행 슬래시 유무까지 discovery가 반환하는 문자열과 완전히 일치해야 합니다. [ReSSO 관리자 가이드](https://github.com/hkjang/ReSSO/blob/f508c7901ad4d0a5437aa87be12710fa1fa37192/docs/ADMIN_GUIDE.md)

이는 **공식 소스와 설정 계약의 대조**입니다. 이번 Hunter의 로컬 모의 OIDC 검증을 실제 운영 ReSSO 계정·사내 프록시·인증서·사용자 정책의 통합 검증으로 표현하지 않습니다. ReSSO의 모든 Keycloak Admin API·SAML·고유 확장과 자동 호환된다는 뜻도 아닙니다.

## Hunter의 자동 진입과 복구

- 관리자 OIDC 사용과 자동 진입이 켜진 경우에만 자동 확인합니다. 자동 옵션을 생략한 기존 OIDC 설정은 켜짐으로 취급합니다.
- 유효한 Hunter 세션이 있으면 discovery 없이 원래 내부 화면으로 이동합니다. 안전한 내부 경로·검색·해시는 최대 4096바이트까지 보존합니다.
- 자동 시도 뒤 10분, 명시 로그아웃 뒤 24시간 동안 브라우저의 자동 재시도를 억제합니다. 암호화 HttpOnly 쿠키를 사용하고 명시 SSO 또는 로컬 로그인 성공으로 복구할 수 있습니다.
- 오류 callback도 state·만료·한 번 사용·현재 설정 지문을 확인합니다. 공급자 오류 설명 원문을 노출하지 않습니다.
- `/login?local=1`은 자동 진입을 건너뛰는 로컬 복구 주소입니다. 브라우저가 IdP에 연결하지 못해 callback이 없으면 자동 복귀를 보장하지 않습니다. IdP 전역 로그아웃은 제공하지 않습니다.

## 방문 추적의 브라우저 격리

HTML sandbox는 스크립트 실행과 같은 권한을 명시적으로 부여하는 구조입니다. Hunter는 별도 프레임에 `allow-scripts`만 부여하고 `allow-same-origin`은 부여하지 않아 앱의 DOM·쿠키·저장소와 분리합니다. 앱 본문에 관리자가 붙여 넣은 코드를 삽입하거나 전체 앱 CSP를 완화하지 않습니다. [WHATWG HTML iframe sandbox](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox), [W3C Content Security Policy sandbox](https://www.w3.org/TR/CSP3/#directive-sandbox)

관리자 세션 전용 설정은 암호화·revision 비교를 적용합니다. 최대 32KiB의 JavaScript 또는 10개 script 태그와 10개 정확한 허용 원점을 지원합니다. 원점 입력은 각300바이트, 정규화한 허용 원점 합계는1536바이트 이하이며 호스트253·DNS라벨63바이트와 IDNA 정규화를 검사합니다. 로그인·관리자·개인화 페이지는 제외하며 일반 메뉴의 고정 `{path,title}`만 전달합니다. 실제 객체 ID·쿼리·해시·사용자 이름·증거·AI 대화는 페이지 이벤트에 넣지 않습니다.

미리보기는 관리자별 5분·한 번 사용의 암호화 초안을 브라우저에서 실행합니다. 형식 검사·코드 로드·bridge 준비는 수집기 실제 접수와 별개입니다. 시험 중 허용한 서버에 합성 이벤트가 전송될 수 있으며 조직에서 승인한 시험 수집기를 사용해야 합니다.

쿠키·localStorage·부모 DOM·eval·iframe에 의존하는 분석 SDK는 이 실행 환경에서 그대로 호환되지 않을 수 있습니다. `hunter:pageview` 이벤트를 사내 수집기 형식으로 변환하는 어댑터를 사용합니다. IP·User-Agent 등 HTTP 기본 정보는 수집 시스템에서 관측될 수 있으므로 완전한 익명성이나 개인정보 무전송을 보장한다고 표현하지 않습니다.

## 검증의 구분

로컬 서명 OIDC 제공자·브라우저·격리 수집기로 기존 세션, 오류 복귀, 현재 권한, 재시도 억제, CSP·메시지 경계와 revision을 확인합니다. 이는 실제 ReSSO 계정·외부 분석 서비스의 운영 수신·통계 정확성 인증과 다릅니다. 릴리즈 파일의 실제 검증 결과는 수행 후 [릴리즈](https://github.com/hkjang/hunter/releases/tag/v1.9.0)에 별도로 기록합니다.
