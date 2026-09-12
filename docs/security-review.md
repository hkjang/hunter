# Hunter 독립 보안 회귀 검증 기록

## v1.5 증거 형식과 기존 자료 복구

발견 건 evidence에 객체·배열 등 문자열이 아닌 값을 직접 보내면 기존 암호화 경로에서 빠질 수 있는 입력 문제를 재현하고 수정했습니다. 새 요청은 구조형 증거를 거부하며, 정상 문자열은 기존 마스킹·길이 제한·암호화 경로를 사용합니다. 현재 DB에 남은 구조형 증거는 키 정합성 확인 후 서버 시작 전에 50행 배치로 정리합니다. 105행의 세 배치 처리·재실행 멱등성과 잠긴 미처리 행을 완료로 간주하지 않는 회귀 검사를 확인했습니다.

복구는 현재 DB에 적용하며 과거 백업·스냅샷·별도 복제본을 소급 정리하지 않습니다. 복구할 행의 잠금이나 오류 때문에 최대 2분 안에 완료하지 못하면 서버를 시작하지 않습니다. 원문 없는 처리 건수 감사를 남기며 관리 절차는 [관리자 가이드](guides/admin-guide.md)에 설명합니다.


**대상: v1.0.0 개발 소스 · 수행일: 2026-09-11**

구현 담당자와 별도로 인증·권한·진단 정책·작업 수명 주기·외부 발송·릴리즈 경로를 검토했습니다. 검토 중 발견한 범위 우회와 상태 경합을 수정한 후, 독립 소스 스냅샷과 로컬 PostgreSQL의 테스트 전용 스키마에서 아래 결과를 확인했습니다.

이 기록은 명시한 코드 경로에 대한 회귀 검증입니다. 모든 보안 취약점의 부재, 전사 운영 성능, 임의 외부 진단 엔진의 안전성을 보증하는 인증 보고서는 아닙니다.

## 실제 재현과 확인한 결과

| 검증 | 재현 조건 | 수정 후 확인한 결과 |
| --- | --- | --- |
| 그래프의 발견 건 권한 | services:read만 가진 개인 키로 /api/findings와 /api/graph 호출 | 직접 발견 건 조회 403, 그래프 응답에 비공개 발견 제목 없음 |
| 대시보드의 진단 권한 | findings:read만 가진 개인 키로 /api/scans와 /api/dashboard 호출 | 직접 진단 조회 403, 대시보드 recent_scans 길이 0 |
| 오래된 개선 요청 저장 | 발송 전 읽은 데이터를 실제 외부 발송 완료 후 저장 시도 | 동시 변경 충돌로 저장 거부, 두 번째 발송 409, 외부 POST 총 1회 |
| 취소된 재검증의 종결 | cancelled 진단을 근거로 기존 헤더 발견 건 해결 시도 | 활성 임대 확인 실패, 발견 건 candidate 유지 |

외부 발송은 테스트용 HTTP 서버가 받은 POST 수를 실제 집계했습니다. 오래된 저장 검증은 HTTP PUT과 같은 persistResource 경로를 사용해 발송 전 읽기 → 발송 완료 → 오래된 저장 순서를 재현했습니다. 취소 검증은 재검증 종결 함수가 임대 없는 상태를 거부하는지 직접 확인했습니다.

핵심 실행 로그:

~~~text
services-only key findings=403 graph=200 confidential-title-leaked=false
findings-only key scans=403 dashboard=200 recent-scans=0
stale PUT rejected=다른 요청이 이 항목을 변경했습니다. 새로고침 후 다시 시도하세요
stale-save-followed-by-dispatch status=409 outgoing-POST-count=1
cancelled-scan resolve-error=활성 재검증 임대가 없어 해결 상태를 확정하지 않았습니다
resulting-finding-status=candidate
PASS
~~~

## 마지막 보완 사항

익명 로그인 요청이 사용자명을 바꿔 비밀번호 검증 부하를 누적할 수 있던 경로에 IP당 120회/분 제한과 프로세스당 검증 동시성 4개를 추가했습니다. 기존 사용자명·IP 조합의 15분·10회 제한도 유지합니다. TestLoginIPAndConcurrencyLimit에서 IP 한도와 동시성 한도를 확인합니다.

만료된 위험 수용은 대시보드가 즉시 열린 위험으로 집계하고, 분 단위 유지보수에서 탐지 후보로 되돌리며 같은 DB 작업으로 감사 기록을 남깁니다. TestExpiredRiskAcceptanceReopens에서 상태 전환, 감사와 반복 실행을 확인합니다.

## 함께 검토한 통제

- 개인 키 권한과 소유자의 현재 역할 권한의 교집합
- 소유자·팀장 팀 범위와 관리자 전체 접근의 구분
- 브라우저 세션 전용 키·프로필 관리, CSRF 확인
- OIDC state·nonce·PKCE·서명·issuer·audience 검증
- 승인 대상의 URL·환경·망 등 변경 시 재승인
- 실행 중 권한·키·대상·범위·정책 변경에 따른 중단
- 외부 엔진 결과 정규화와 원문 비밀값 제외
- 임대·취소와 재검증 종결 상태의 일관성
- 서비스 이미지만 Docker save와 gzip으로 릴리즈하는 경로

전체 자동 테스트와 브라우저 검증은 저장소의 테스트 및 캡처 스크립트에서 별도로 수행합니다. 이 독립 검증 기록에는 확인하지 않은 성능 수치, 모의 해킹 성공률, 취약점 커버리지 수치를 넣지 않았습니다.

## 독립 재실행

[검증 소스](verification/independent-review_test.go.txt)는 같은 패키지의 기존 testApp·request 테스트 도우미를 사용합니다. 저장소의 운영 코드를 변경하지 않고 임시 디렉터리에 복사하여 실행할 수 있습니다.

**테스트 전용 PostgreSQL에만 실행하세요.** testApp은 고유한 임시 스키마를 만들고 종료 시 해당 스키마만 삭제합니다. 아래 명령을 실행하기 전에 HUNTER_TEST_DSN을 테스트 실행 환경에 안전하게 제공해야 합니다.

~~~sh
review_dir="$(mktemp -d)"
mkdir -p "$review_dir/internal/app"
cp go.mod go.sum "$review_dir/"
cp internal/app/*.go internal/app/*.sql internal/app/*.json "$review_dir/internal/app/"
cp docs/verification/independent-review_test.go.txt "$review_dir/internal/app/review_test.go"
go -C "$review_dir" test ./internal/app -run '^TestReview' -count=1 -v
~~~

향후 내부 함수 서명이 바뀌면 검증 소스도 해당 릴리즈의 구현에 맞게 갱신합니다. 운영 설정의 네 환경변수와 테스트용 HUNTER_TEST_DSN은 서로 다른 실행 용도입니다.

[관리자 가이드](guides/admin-guide.md) · [사용자 가이드](guides/user-guide.md)
