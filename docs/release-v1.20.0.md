# Hunter v1.20.0

발견 건 **일괄 변경**의 조치 기한 폼이 서버가 읽을 수 없는 연도를 제출하지 않도록 보내는 값에서 막은 릴리즈입니다. 유효한 기한이 만드는 요청은 한 글자도 달라지지 않으며 서버 API·권한·감사 기록, 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- **같은 변경의 담당자·상태까지 되돌려졌습니다.** 일괄 변경 폼의 `findingBulkPatch`(`web/src/finding-bulk-state.ts`)는 `new Date(...).toISOString()` 결과를 검사 없이 `due_date` 로 보냈습니다. ECMA-262 는 UTC 순간이 0000~9999 를 벗어나면 확장 연도(`+YYYYYY`/`-YYYYYY`)를 내놓는데, 서버 `validateFindingOpsResource`(`internal/app/finding_ops.go`)는 `time.Parse(time.RFC3339, s)` 로만 읽고 그 layout 은 부호 없는 네 자리 연도만 받습니다. 그래서 `internal/app/finding_bulk.go` 가 요청 전체를 `400` 으로 돌려보내, 같은 변경에 담아 보낸 담당자와 진행 상태까지 함께 취소됐습니다.
- **브라우저 시간대가 수락·거절을 갈랐습니다.** 넘어가는 쪽을 정하는 것은 입력한 날짜만이 아닙니다. 타이핑할 수 있고 사양상 유효한 `datetime-local` 값 `9999-12-31T23:59` 은 UTC 동쪽에서는 범위 안이지만, 서쪽 시간대(America/New_York)에서는 유한한 값인 채로 `+010000-01-01T04:59:00.000Z` 로 직렬화됩니다. 즉 같은 입력이 사용자의 시간대에 따라 저장되거나 전체 취소됐습니다.
- **보내는 문자열을 검사해 기한 칸에서 안내합니다.** 이제 검사 대상은 `input.due` 가 아니라 **실제로 제출하는 문자열**입니다. 네 자리 연도로 시작하지 않으면 요청을 만들지 않고 "조치 기한을 세계 표준시로 바꾸면 서버가 받을 수 있는 연도 범위를 벗어납니다. 더 가까운 기한을 입력하세요." 를 기한 칸 옆에 표시합니다. 범위 안의 기한이 만드는 요청 본문은 달라지지 않습니다.

## 운영 조건과 한계

서버 계약은 바꾸지 않았습니다. `due_date` 는 그대로 네 자리 연도 RFC3339 만 받으며 API 필드·권한 검사·감사 기록·최대 100개 일괄 변경과 각 항목의 `updated_at` 비교, 한 항목 충돌 시 전체 롤백 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 한 개입니다. 과제 단계에서 가정했던 다섯 자리 연도 입력은 재현되지 않았습니다. V8 이 `new Date("10000-01-01T00:00")` 를 Invalid Date 로 만들어 기존 유한성 검사가 이미 막기 때문이며, 실제 도달 경로는 위의 네 자리 연도 + UTC 서쪽 시간대입니다. 같은 모양의 날짜 직렬화가 공통 자원 폼(`web/src/resources.tsx`)에도 있으나 이번 범위에 넣지 않았습니다.

## 검증과 배포

새 공유 벡터 `internal/app/testdata/finding-bulk-due-date.json` 은 (시간대, 입력) 쌍마다 보내는 문자열과 서버 판정을 적습니다. Go 는 `TestFindingBulkDueDateSharedVectors` 에서 `validateFindingBulk` 로 그 판정을 확인하고(PostgreSQL 없이 실행), 화면 시험은 `process.env.TZ` 를 바꿔 `findingBulkPatch` 가 거절하거나 `accepted` 로 표시된 문자열만 제출하는지 단언합니다. 수정 전 그 화면 시험 하나가 실패하는 것과, 같은 벡터가 수정 전에도 Go 쪽에서는 전부 통과하는 것을 먼저 확인했습니다.

`npm --prefix web ci` 후 `npm --prefix web test` 가 `web/tests` 19개 파일에서 106개 검사를 실행해 모두 통과했고 실패·건너뜀은 0개입니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.20.0` · 유일한 첨부 자산: `hunter-v1.20.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.19.0 릴리즈 노트](release-v1.19.0.md)
