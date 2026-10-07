# Hunter v1.24.0

발견 건의 **기여 점수**가 어디서 읽어도 같은 하나의 값으로 저장되도록 고치고, 그 칸과 예약의 **실행 간격 (분)** 이 서버가 실제로 받는 범위를 선언하도록 맞춘 릴리즈입니다. 범위 안의 정수가 만드는 요청은 한 글자도 달라지지 않으며 서버 계약·권한·감사 기록, 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- **한 발견 건의 기여 점수가 화면마다 다른 값이었습니다.** 자원 저장 처리기는 `internal/app/server.go:129` 에서 `json.NewDecoder` 로 본문을 읽고 `UseNumber` 를 쓰지 않으므로 JSON 숫자는 `float64` 로 도착하고, `number()`(`internal/app/domain.go:115`)가 `int(n)` 으로 돌려줍니다. `validateScope`·`validatePolicy`·`validateSchedule` 은 그렇게 잘린 정수를 자원 자료에 **되쓰는데** 발견 건 분기만 범위를 검사하고 되쓰지 않았습니다. 그래서 제출한 `7.5` 는 검사만 `7` 로 통과하고 저장에는 `7.5` 가 남아, 대시보드의 기여 집계와 보고서 내보내기 CSV 의 **기여 점수** 열은 `7`(`number()`·`strconv.Itoa`)을, 저장된 JSON 을 그대로 받는 **보안 기여** 화면(`web/src/pages.tsx`)은 `Number()` 로 `7.5` 를 보여 줬습니다. `openapi.json` 은 그 필드를 양쪽에 `"type": "integer"` 로 선언합니다.
- **0.5 는 한 화면에만 있고 다른 화면에는 없었습니다.** 대시보드 집계는 `if points := number(f, "contribution_points", 0); points > 0` 으로 거르므로 저장된 `0.5` 는 `0` 이 되어 집계에서 빠지고, **보안 기여** 화면은 `Number(r.contribution_points) > 0` 으로 거르므로 같은 발견 건이 그 화면에는 올라왔습니다. 같은 점수가 한 곳에서는 인정된 기여이고 다른 곳에서는 없는 기여였습니다.
- **기여 점수 칸은 상한을 선언하지 않았습니다.** 이 칸은 Mantine `NumberInput` 이고 `clampBehavior` 기본값이 `"blur"` 이므로 선언한 `min`·`max` 는 참고 문구가 아니라 **칸을 떠날 때 타이핑한 값을 그 경계로 옮기는 동작**입니다. 기여 점수는 `min: 0` 만 선언하고 `max` 가 없어 관리자를 서버가 받는 `10000` 위로 그냥 올려 보냈고, 조작자는 저장한 다음에야 `400` 을 봤습니다.
- **두 칸 모두 소수점을 막지 않았습니다.** 공유 렌더러는 선언의 `integer` 를 `allowDecimal={false}` 로 바꾸는데(`web/src/resources.tsx:1021`) 기여 점수와 실행 간격에는 그 잠금이 없었습니다. 실행 간격은 `validateSchedule` 이 잘린 정수를 되쓰므로 제출한 `1440.5` 가 안내 없이 `1440` 으로 저장되고, `4.5` 는 `4` 로 잘려 **넘은 것처럼 보이지 않는 하한**(`5`)을 넘었다는 이유로 거절됐습니다. 이제 두 칸 모두 입력에서 소수점을 막습니다.
- **범위 검사가 되쓰는 함수로 옮겨졌습니다.** 발견 건 분기에 흩어져 있던 `number(m, "contribution_points", 0)` 두 번의 검사가 `validateContributionPoints`(`internal/app/domain.go`) 하나로 모였고, 이 함수는 형제 검증들과 같게 검사한 정수를 `m["contribution_points"] = points` 로 되씁니다. 저장되는 값이 하나이므로 세 읽는 쪽이 같은 수를 봅니다.
- **상한·하한·정수 잠금은 공유 표 하나에서 옵니다.** `web/src/resource-form-state.ts` 의 `resourceNumberBounds` 에 `findings.contribution_points`(`0`~`10000`)와 `schedules.interval_minutes`(`5`~`10080`)가 더해져 v1.23.0 의 일곱 칸과 함께 아홉 칸이 되고, 각 선언이 그것을 펼쳐 씁니다. 하한은 모두 서버의 실제 하한입니다. 기여 점수는 `0` 부터, 실행 간격은 `5` 부터이며 `validateScope`·`validatePolicy` 의 일곱 칸은 그 표 둘째 칸이 대체값이라 여전히 `1` 부터입니다.

## 운영 조건과 한계

서버 계약은 바꾸지 않았습니다. 기여 점수는 그대로 `0`~`10000`, 실행 간격은 그대로 `5`~`10080` 이고 두 필드의 API 형식·권한 검사·감사 기록, 기여 점수를 관리자·팀장만 설정할 수 있다는 규칙(`!managerial(u)` 이면 이전 값으로 되돌림), 일반 자원 수정의 `expected_updated_at` 비교와 409 입력 보존 규칙도 그대로입니다. 프로덕션 변경은 `internal/app/domain.go`·`web/src/resource-form-state.ts`·`web/src/resources.tsx` 세 개이며, 범위 안의 정수가 만드는 요청 본문은 한 글자도 달라지지 않습니다.

이번 릴리즈는 자료 이전을 포함하지 않습니다. 이전 버전에서 소수점으로 저장된 기여 점수는 그대로 남아 있어 대시보드 집계와 **보안 기여** 화면이 계속 다른 수를 보여 줍니다. 해당 발견 건을 관리자가 한 번 다시 저장하면 `validateContributionPoints` 가 정수로 정리합니다. 상한 없는 칸이 서버 범위를 넘겨 `400` 으로 잃어버린 입력과 실행 간격에서 잘려 저장된 과거 값도 되살리지 않습니다. 폼 제출 값 검사는 v1.21.0 에서 일시 칸, v1.22.0 에서 JSON 칸, v1.23.0 에서 진단 허용 범위·실행 정책의 숫자 칸에 들어왔고 이번에는 같은 폼의 남은 숫자 칸 두 개와 그 값의 저장을 맞췄습니다.

## 검증과 배포

공유 벡터 `internal/app/testdata/resource-number-bounds.json` 이 경계 7행에서 9행으로, 소수점 사례 9개에서 13개로 늘었습니다. Go 쪽 `internal/app/resource_number_bounds_test.go` 는 그 칸을 **다시 적지 않고 거기서 탐침을 만들어** 실제 `validateScope`·`validatePolicy`·`validateContributionPoints`·`validateSchedule` 에 넣습니다. `min` 은 통과, `min-1` 은 거절, `max` 는 통과, `max+1` 은 서버 자신의 문구로 거절되는지 확인하므로 그 두 칸이 서버의 실제 허용 범위임이 벡터 밖에서 증명됩니다. 새 시험 `TestContributionPointsStoredValueReadsTheSameEverywhere` 는 수락된 소수점을 검증기에 넣은 뒤 저장될 값을 다시 직렬화해, 브라우저가 받는 수와 `number()` 가 읽는 수가 같고 `> 0` 판정도 갈리지 않는지 단언합니다. 화면 쪽 `web/tests/resource-number-bounds.test.mjs` 는 같은 벡터로 `resourceNumberBounds` 가 정확히 일치하는지, 아홉 선언이 모두 그 표를 펼쳐 쓰는지, 서버가 자르는 칸이 정수 전용으로 선언됐는지 확인합니다.

`npm --prefix web ci` 후 `npm --prefix web test` 가 `web/tests` 20개 파일에서 113개 검사를 실행해 모두 통과했고 실패·건너뜀은 0개입니다. 수정 전 화면 선언으로 되돌리면 화면 시험 세 개만 실패해 110통과/3실패가 되는 것을 먼저 확인했습니다. `validateContributionPoints` 에서 되쓰기 한 줄만 지우면 `go test -run 'ResourceNumberBounds|ContributionPoints' ./internal/app` 이 "the browser is handed 7.5 while the leaderboard and the CSV read 7" 로 실패합니다. 되쓰기가 이 릴리즈의 핵심이라는 근거이며, 그 한 줄이 없으면 화면 시험은 모두 통과한 채 저장된 값만 어긋납니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

브라우저에서 NumberInput 을 직접 타이핑하고 칸을 떠나 clamp 동작을 눈으로 확인하거나, PostgreSQL 이 붙은 서버에 소수점 점수를 실제로 저장해 두 화면의 차이를 재현하지는 않았습니다. PostgreSQL 이 필요한 Go 전체 시험은 이 환경에서 실행하지 않았습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.24.0` · 유일한 첨부 자산: `hunter-v1.24.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.23.0 릴리즈 노트](release-v1.23.0.md)
