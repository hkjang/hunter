# Hunter v1.21.0

**공통 자원 폼**의 일시 칸 네 곳이 서버가 읽을 수 없는 연도를 제출하지 않도록 보내는 값에서 막은 릴리즈입니다. 범위 안의 일시가 만드는 요청은 한 글자도 달라지지 않으며 서버 API·권한·감사 기록, 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- **입력한 일시가 서버 오류로 사라졌습니다.** 공통 자원 폼의 `formBody`(`web/src/resources.tsx`)는 `new Date(value).toISOString()` 결과를 검사 없이 요청 본문에 넣었습니다. ECMA-262 는 UTC 순간이 0000~9999 를 벗어나면 확장 연도(`+YYYYYY`/`-YYYYYY`)를 내놓는데, 이 네 칸을 읽는 서버 경로는 모두 `time.Parse(time.RFC3339, s)` 로만 읽고 그 layout 은 부호 없는 네 자리 연도만 받습니다. 발견 건의 조치 기한(`validateFindingOpsResource`, `internal/app/finding_ops.go`)과 위험 수용 만료 일시(`validateResource`, `internal/app/domain.go`), 예약의 첫 실행 일시(`validateSchedule`, `internal/app/domain_schedules.go`), 범위의 만료 일시(`validateScope`, `internal/app/policy.go`)가 모두 그 문자열을 `400` 으로 거절하므로, 조작자가 입력한 값은 손댈 수 없는 서버 오류로 사라졌습니다.
- **브라우저 시간대가 수락·거절을 갈랐습니다.** 넘어가는 쪽을 정하는 것은 입력한 날짜만이 아닙니다. 타이핑할 수 있고 사양상 유효한 `datetime-local` 값 `9999-12-31T23:59` 은 UTC 동쪽에서는 범위 안이지만, 서쪽 시간대(America/New_York)에서는 유한한 값인 채로 `+010000-01-01T04:59:00.000Z` 로 직렬화됩니다. 즉 같은 입력이 사용자의 시간대에 따라 저장되거나 거절됐습니다.
- **번역되지 않은 브라우저 문구가 보였습니다.** ECMAScript 시간 값 범위를 벗어나는 입력에서는 `toISOString` 이 `RangeError` 를 던지고, 그 예외가 `formBody` 를 그대로 빠져나가 폼 오류 띠에 영어 "Invalid time value" 로 표시됐습니다.
- **보내는 문자열을 검사해 해당 칸 이름으로 안내합니다.** 이제 검사 대상은 타이핑한 값이 아니라 **실제로 제출하는 문자열**입니다. 네 자리 연도로 시작하지 않으면 요청을 만들지 않고 "<칸 이름>: 세계 표준시로 바꾸면 서버가 받을 수 있는 연도 범위를 벗어납니다. 더 가까운 일시를 입력해 주세요." 를 표시하며, 범위를 벗어난 입력의 `RangeError` 도 같은 한국어 안내로 바뀝니다. 범위 안의 일시가 만드는 요청 본문은 달라지지 않고, 빈 칸은 그대로 빈 문자열로, 필수 빈 칸은 기존 필수 항목 문구로 남습니다.

## 운영 조건과 한계

서버 계약은 바꾸지 않았습니다. 네 필드는 그대로 네 자리 연도 RFC3339 만 받으며 API 필드·권한 검사·감사 기록, 일반 자원 수정의 `expected_updated_at` 비교와 409 입력 보존 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 두 개이며, 제출 본문을 만드는 `formBody` 를 `web/src/resource-form-state.ts` 의 `resourceSubmitBody` 로 옮겨 그 함수가 보내는 문자열을 검사로 직접 확인할 수 있게 한 것이 변경의 전부입니다. JSON 칸 해석과 필수 칸 검사의 동작·문구는 옮기기 전과 같습니다. v1.20.0 의 발견 건 일괄 변경 폼은 이미 같은 방식으로 막혀 있으며, 이번 릴리즈는 v1.20.0 노트가 범위에서 제외했다고 적은 공통 자원 폼을 처리합니다.

## 검증과 배포

새 공유 벡터 `internal/app/testdata/resource-datetime.json` 은 (시간대, 입력) 쌍마다 보내는 문자열과 하나의 판정을 적습니다. Go 는 `TestResourceDateTimeSharedVectors` 에서 벡터 14개를 `validateFindingOpsResource`·`validateSchedule`·`validateScope` 에 직접 넣어 그 판정이 서버의 실제 판정임을 확인하고(PostgreSQL 없이 실행), 화면 시험은 `process.env.TZ` 를 바꿔 `resourceSubmitBody` 가 거절하거나 `accepted` 로 표시된 문자열만 제출하는지 단언합니다. `validateResource` 는 서비스 조회가 필요해 DSN 없이 부를 수 없으므로, 같은 `time.Parse(time.RFC3339, s)` + 미래 시각 쌍을 적용하는 `validateScope` 쪽에서 같은 문자열로 확인했습니다. 수정 전 그 화면 시험 하나가 실패하는 것(107통과/1실패)과, 같은 벡터가 수정 전에도 Go 쪽에서는 전부 통과하는 것을 먼저 확인했습니다.

`npm --prefix web ci` 후 `npm --prefix web test` 가 `web/tests` 19개 파일에서 108개 검사를 실행해 모두 통과했고 실패·건너뜀은 0개입니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.21.0` · 유일한 첨부 자산: `hunter-v1.21.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.20.0 릴리즈 노트](release-v1.20.0.md)
