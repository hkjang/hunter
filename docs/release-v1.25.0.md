# Hunter v1.25.0

발견 건 **조치 담당자**의 한도를 한 곳에 모으고, 지금까지 이 칸을 읽지 않던 발견 건 저장 경로에도 같은 규칙을 적용한 릴리즈입니다. 규칙을 통과하는 이름이 만드는 요청은 한 글자도 달라지지 않으며 서버 API 경로·권한 검사·감사 기록, 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- **같은 이름을 한 화면은 거절하고 다른 화면은 저장했습니다.** `data->>'assignee'` 를 쓰는 경로는 네 개인데 검사하는 쪽은 둘뿐이었습니다. 일괄 변경 `validateFindingBulk`(`internal/app/finding_bulk.go:60`)와 ITSM 동기화(`internal/app/automation_workflows_tickets.go:50-62`)는 UTF-8 200바이트 초과와 제어문자를 거절하고 양끝 공백을 제거해 저장했지만, 발견 건 하나를 저장하는 경로 `validateResource`(`internal/app/domain.go:468`)의 발견 건 분기는 이 칸을 **읽지 않았습니다**. 그래서 상세 폼과 자원 API 는 다른 두 경로가 거절하는 이름 — 200바이트를 넘는 문자열, 줄바꿈·탭·NUL 이 섞인 문자열, 애초에 문자열이 아닌 값 — 을 그대로 저장할 수 있었습니다.
- **검사받지 않은 문자열이 그대로 밖으로 나갔습니다.** 저장된 담당자는 발견 건 CSV 내보내기, 조회 GraphQL 과 알림 본문의 `finding.assignee` 변수로 나갑니다. 저장 시점에 거르지 않으면 그 세 출구에 한도를 넘는 문자열이나 제어문자가 섞인 이름이 그대로 실립니다.
- **공백만으로 이루어진 이름은 같은 발견 건을 둘로 갈랐습니다.** 조치함 집계 SQL(`internal/app/finding_ops.go:246`)은 `btrim(coalesce(data->>'assignee',''))` 를 빈 문자열과 비교하므로 `"   "` 를 **미배정**으로 셉니다. 상세 화면(`web/src/triage.tsx:425`)은 `item.assignee || "미지정"` 이라 비어 있지 않은 문자열을 참으로 보므로 같은 행을 **배정됨**으로 보여 줍니다. 한 발견 건이 두 세는 쪽에 서로 다른 발견 건이었습니다. 알림 수신자 매칭(`internal/app/notification_automation_recipients.go:78`)은 세 번째 읽기가 아닙니다. 원문 문자열을 `u.ID`·`u.Username` 과 비교하므로 공백만인 이름은 어떤 사용자와도 맞지 않아 집계 SQL 과 같은 방향, 즉 미배정으로 동작합니다.
- **규칙이 자유 함수 하나로 모였습니다.** `validateFindingAssignee`(`internal/app/finding_ops.go`)를 `validateResource` 의 발견 건 분기와 일괄 변경이 함께 호출하고, `finding_bulk.go` 의 인라인 조건과 그 안에 복제돼 있던 오류 문구는 사라졌습니다. 오류 문구는 일괄 변경이 이미 쓰던 그 문장 하나이며, 거절된 값이 보호 대상이고 오류 본문은 응답으로 되돌아가므로 제출한 이름을 따라 적지 않습니다. 200은 룬이 아니라 바이트 예산입니다. 일괄 변경이 처음부터 `len()` 으로 재 온 값이기 때문입니다.
- **이미 저장된 값은 계속 편집할 수 있습니다.** `saveDomain` 은 요청 본문을 기존 자료 위에 병합한 뒤 검증하므로, 이 칸을 건드리지 않은 `PUT` 은 저장된 값과 같은 값으로 도착합니다. 그 경우 규칙을 건너뛰므로 규칙 이전에 들어온 담당자가 그 행의 **이후 모든 수정을 400 으로 바꾸지 않습니다**. 비교는 `==` 가 아니라 양쪽을 JSON 으로 직렬화해서 합니다. 이 칸을 형 검사한 코드가 없었으므로 저장된 값이 객체나 배열일 수 있고, 그런 값을 담은 `any` 두 개를 `==` 로 비교하면 차이를 보고하는 대신 "comparing uncomparable type" 으로 패닉해 저장 경로 전체가 죽습니다. 직렬화할 수 없는 값은 같음이 아니라 다름으로 세어 규칙을 계속 적용합니다.
- **일괄 변경의 `null` 은 그대로 거절합니다.** 패치에 필드 이름을 적는 것은 저장 경로가 지나치는 "제출하지 않음" 이 아닙니다. 일괄 변경에는 비교할 이전 값도 없습니다. 선택한 모든 발견 건에 같은 새 담당자를 쓰는 요청이기 때문입니다.
- **계약 문서가 실제 한도를 적습니다.** `internal/app/openapi.json` 의 발견 건 스키마 두 곳에 `maxLength: 200`·`x-max-bytes: 200` 과 한국어 설명이 들어가, 200바이트·제어문자 금지·양끝 공백 제거·빈 문자열의 담당자 해제와 규칙 이전 값의 취급을 명시합니다.

## 운영 조건과 한계

서버 API 경로·권한 검사·감사 기록은 바꾸지 않았고, 규칙을 통과하는 이름이 만드는 요청 본문도 달라지지 않습니다. 프로덕션 변경은 `internal/app/finding_ops.go`(규칙 추가)·`internal/app/domain.go`(호출 한 줄)·`internal/app/finding_bulk.go`(인라인 조건 제거)와 `internal/app/openapi.json` 의 선언이며 화면 변경은 없습니다.

`data->>'assignee'` 의 **네 번째 쓰는 쪽인 스캐너 결과 수입은 이번 범위에 들어 있지 않습니다**. `internal/app/imports.go:102` 는 올려받은 JSON 의 `assignee` 를 `str()` 로 꺼내 `ingestFindings` 에 넘기고, 그 함수는 행을 직접 `INSERT`/`UPDATE`(`imports.go:297`·`304`) 하므로 `validateResource` 를 거치지 않습니다. 이름 하나가 수입 묶음 전체를 실패시켜야 하는지, 아니면 그 행만 건너뛰어야 하는지는 대화형 저장 한 건을 거절하는 것과 다른 결정이라 후속 작업으로 기록합니다. 그때까지 두 가지를 함께 보아야 합니다. 이 릴리즈 이후에도 그 경로는 규칙 밖 이름을 계속 만들고, 위의 같은 값 건너뛰기가 저장된 값과 같은 값을 면제하므로 그렇게 들어온 이름은 그 발견 건의 이후 `PUT` 마다 계속 면제됩니다.

이번 릴리즈는 자료 이전을 포함하지 않습니다. 이미 저장된 규칙 밖 담당자는 그대로 남아 있으며, 공백만인 이름이 들어 있는 발견 건은 조치함 집계와 상세 화면이 계속 다르게 셉니다. 해당 발견 건의 담당자를 한 번 다시 입력하면 그때 규칙이 적용됩니다.

## 검증과 배포

새 시험 `internal/app/finding_assignee_test.go` 는 다섯 개입니다. `TestFindingAssigneeRule` 은 200바이트 경계와 201바이트, 200룬이 200바이트를 넘는 경우, 멀티바이트 룬이 경계를 넘기는 경우, 줄바꿈·탭·NUL, 문자열이 아닌 값, 양끝 공백 제거와 공백만인 이름이 빈 문자열이 되는 것까지 16가지를 확인합니다. `TestFindingAssigneeKeepsExistingValuesEditable` 은 규칙 이전 값이 그대로 있는 `PUT`, 그 값을 유효한 값으로 바꾸는 `PUT`, 다른 규칙 밖 값으로 바꾸는 `PUT`, 비우는 `PUT` 과 깨끗한 행에 처음 들어오는 규칙 밖 값을 구분합니다. `TestFindingAssigneeIsWiredIntoResourceValidation` 은 규칙이 `validateResource` 에 실제로 연결됐는지 확인하고, `TestFindingAssigneeToleratesUncomparableStoredValues` 는 객체·배열·중첩 배열이 저장된 행을 열 가지로 통과시키며, `TestFindingAssigneeBulkUsesTheSameRule` 은 일괄 변경이 같은 함수와 같은 문구를 쓰는지 확인합니다.

`go test -run Assignee -count=1 ./internal/app` 가 통과합니다. 실패 경로도 확인했습니다. `domain.go` 의 호출 세 줄을 지우면 `TestFindingAssigneeIsWiredIntoResourceValidation` 이 "want 조치 담당자는 줄바꿈 없이 UTF-8 200바이트 이하로 입력하세요" 로 실패하고, `sameJSONValue(previous, value)` 를 `previous == value` 로 되돌리면 `TestFindingAssigneeToleratesUncomparableStoredValues` 가 `panic: comparing uncomparable type map[string]interface {}` 로 죽습니다. 두 줄이 각각 이 릴리즈의 서로 다른 부분이라는 근거입니다.

`npm --prefix web ci` 후 `npm --prefix web test` 가 `web/tests` 20개 파일에서 113개 검사를 실행해 모두 통과했고 실패·건너뜀은 0개입니다. 화면 코드는 이번 변경에 포함되지 않으므로 이 수는 v1.24.0 과 같습니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

PostgreSQL 이 붙은 서버에 공백만인 담당자를 실제로 저장해 조치함 집계와 상세 화면의 수가 갈리는 것을 재현하지는 않았습니다. 두 읽는 쪽의 판정 차이는 집계 SQL 의 `btrim(coalesce(...))` 비교와 화면의 `item.assignee ||` 표현을 직접 읽어 확인했습니다. PostgreSQL 이 필요한 Go 전체 시험은 이 환경에서 실행하지 않았습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.25.0` · 유일한 첨부 자산: `hunter-v1.25.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.24.0 릴리즈 노트](release-v1.24.0.md)
