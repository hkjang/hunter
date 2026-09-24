# Hunter v1.13.0

**다른 서비스로 보내기**의 표 발급에 **사용자당 미사용 표 20개 상한**을 둔 릴리즈입니다. 표 하나가 암호화한 실행 보고서 전체를 함께 보관하므로 같은 호출이 반복되어도 `handoff_claims` 가 끝없이 늘지 않게 막습니다. 기능·설정·기본값은 달라지지 않으며 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- `POST /api/v1/handoff/claims` 는 표를 발급하기 전에 만료 행을 정리한 뒤, **같은 트랜잭션에서** 그 사용자의 아직 쓰지 않은(만료 전·미수령) 표를 셉니다. 20개 이상이면 표를 만들지 않고 `429` 와 "발급했지만 아직 쓰지 않은 표가 너무 많습니다. 잠시 후 다시 시도하세요" 로 거절합니다. 거절에는 `handoff_claims` 행도 감사 기록(`agent.handoff`)도 남지 않습니다.
- 상한은 **사용자별**입니다. 다른 사람이 같은 실행으로 표를 발급하는 데에는 영향을 주지 않으며, 내 표 하나를 받는 쪽이 받아 가거나 5분 TTL 이 지나면 곧바로 자리가 하나 생깁니다.
- 화면 사용에는 변화가 없습니다. 실행 상세의 **실행 보고서 → 다른 서비스로 보내기**는 한 번 누를 때 표 하나를 만들어 바로 넘기므로, 상한에 닿는 것은 스크립트가 표를 받아 가지 않고 반복 호출하는 경우입니다.

## 운영 조건과 한계

상한은 근사값입니다. 동시에 들어온 두 호출이 같은 수를 읽어 둘 다 통과할 수 있으며, 목적은 정확한 개수 제한이 아니라 반복 호출이 표 테이블을 채우지 못하게 하는 것입니다. 관리자 설정 항목은 추가하지 않았고 값은 코드의 20으로 고정입니다. 받는 쪽 서비스와 허용 목록, 기본 꺼짐 동작, 표의 1회·5분·SHA-256 다이제스트 저장과 감사 기록 범위는 v1.11.0 과 같습니다.

## 검증과 배포

Go 테스트 `TestHandoffClaimsPerUserCap` 을 추가해 20개 발급 `201` → 21번째 `429`(행·감사 기록 없음) → 다른 사용자 `201` → 표 수령 뒤 `201` → 만료 뒤 `201` 을 실제 DB 행 수와 함께 확인했습니다. 릴리즈 커밋에서 `go vet`, 임시 PostgreSQL 컨테이너의 `go test -race`, `npm test`, `npm run build`(tsc 포함), `node scripts/render-guides.mjs`, `node scripts/check-docs.mjs`, `node scripts/verify-pentagi.mjs`, `bash -n scripts/release.sh`, `python3 -m py_compile scripts/release-notes.py` 를 실행했습니다. 최종 게시 커밋의 CI와 공개 아카이브 다운로드 검증은 실제 완료한 뒤 [릴리즈 본문](https://github.com/hkjang/hunter/releases/tag/v1.13.0)에 기록합니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 관리자 가이드 §5.7·README·llms.txt·openapi.json 을 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.13.0` · 유일한 첨부 자산: `hunter-v1.13.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.12.0 릴리즈 노트](release-v1.12.0.md)
