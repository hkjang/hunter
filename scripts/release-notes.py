#!/usr/bin/env python3
"""Write exact release Markdown without passing its content through a shell."""
import hashlib
from pathlib import Path
import re
import sys

tag, archive, output = sys.argv[1:]
if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag):
    raise SystemExit("Invalid release tag")
path = Path(archive)
if path.name != f"hunter-{tag}.tar.gz":
    raise SystemExit("Archive filename does not match release tag")
with path.open("rb") as stream:
    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
tick = chr(96)
fence = tick * 3
version = tuple(int(part) for part in tag[1:].split("-", 1)[0].split("."))
features = ""
if version >= (1, 23, 0):
    features = """### 진단 허용 범위·실행 정책 — 숫자 칸이 서버가 받는 범위를 선언합니다

- **폼이 조작자를 서버가 거절하는 값으로 데려갔습니다**: 두 자원의 숫자 칸 일곱 개는 Mantine `NumberInput` 이고 이 컨트롤의 `clampBehavior` 기본값은 `"blur"` 입니다. 선언한 `min`·`max` 는 참고 문구가 아니라 칸을 떠날 때 타이핑한 값을 그 경계로 옮기는 동작입니다. 그런데 선언한 상한은 `internal/app/policy.go` 의 `validateScope`·`validatePolicy` 가 판정하는 표와 달라, 폼이 동시 실행 상한 `20`(서버는 `1`), 최대 요청 수 `1000`(서버는 `100`), 실행 제한 시간 `600`(서버는 `300`), 초당 최대 요청 수 `100`(서버는 `5`)까지 올려 준 뒤 저장한 다음에야 `400` 이 돌아왔습니다.
- **1 미만의 초당 요청 수는 0 으로 잘려 거절됐습니다**: 자원 저장 처리기는 `json.NewDecoder` 로 `UseNumber` 없이 본문을 읽고 `number()`(`internal/app/domain.go`)가 `int(n)` 을 돌려줍니다. 검사는 `n < 1 || n > b.max` 이므로 옛 하한 `0.1` 부터 `0.9` 까지 모든 값은 `0` 으로 잘려, 타이핑한 값이 넘은 것처럼 보이지 않는 하한을 넘었다는 이유로 거절됐습니다.
- **소수점은 말없이 버려졌습니다**: 두 검증은 잘린 정수를 `m[b.k] = n` 으로 되써 저장하므로 제출한 `2.7` 은 `400` 이 아니라 아무 안내 없이 `2` 로 저장됐습니다. 이제 정수 전용으로 선언한 칸은 입력에서 소수점을 막습니다. 이 잠금은 선언에서 읽으므로 발견 건의 기여 점수와 예약의 반복 간격 같은 다른 숫자 칸은 그대로입니다.
- **상한은 공유 표 하나에서 오고 하한은 1 로 둡니다**: 일곱 칸의 `min`·`max`·정수 잠금이 `web/src/resource-form-state.ts` 의 `resourceNumberBounds` 한 곳에 있고 각 선언이 그것을 펼쳐 씁니다. 서버 표의 둘째 칸은 하한이 아니라 값이 없거나 숫자가 아닐 때의 대체값이므로 일곱 칸 모두 `1` 부터 받습니다. 하한을 올리면 서버가 받는 더 안전한 쪽 값을 폼이 거절하고 이미 저장된 작은 값이 칸을 지나가는 것만으로 올라가므로, 공유 하한은 서버의 실제 하한이며 이 값이 올라가면 Go 시험이 실패합니다.

서버 계약은 바꾸지 않았습니다. 일곱 필드의 API 형식·권한 검사·감사 기록과 두 검증의 표, 일반 자원 수정의 `expected_updated_at` 비교와 409 입력 보존 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 두 개이며 Go 프로덕션 변경은 없고, 범위 안의 값이 만드는 요청 본문은 한 글자도 달라지지 않습니다. 이전 버전에서 서버 범위를 벗어난 상한까지 올라갔다 잃은 입력과 소수점이 잘려 저장된 과거 값은 자동으로 되돌리지 않으므로 해당 범위·정책의 값을 다시 확인해야 합니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

"""
elif version >= (1, 22, 0):
    features = """### 공통 자원 폼 — JSON 칸을 비우면 그 칸이 선언한 그릇을 제출합니다

- **비운 JSON 칸이 모두 똑같이 `{}` 를 보냈습니다**: 제출 본문을 만드는 `resourceSubmitBody`(`web/src/resource-form-state.ts`)는 JSON 칸마다 `JSON.parse(values[f.key] || "{}")` 를 썼습니다. 빈 문자열이 `"{}"` 로 바뀌므로 칸의 선언과 무관하게 객체 `{}` 가 저장됐고, 서비스의 추가 공격 표면(`targets`)은 `default: []` 로 선언하므로 배열을 선언한 칸만 선언과 다른 그릇을 저장했습니다. `targets` 의 자료형을 확인하는 서버 검증은 없어 `400` 도 나지 않았습니다.
- **서비스의 공격 표면이 말없이 그려지지 않았습니다**: 자산 그래프는 그 값을 `internal/app/domain.go` 에서 `s["targets"].([]any)` 로 읽습니다. 저장된 `{}` 는 이 타입 단정에 실패하고 `, ok` 형태 단정은 오류를 내지 않으므로, 그 서비스의 추가 공격 표면이 아무 안내 없이 사라졌습니다.
- **진단 대상 승인이 말없이 해제됐습니다**: 같은 파일의 재승인 비교는 `targets` 를 포함한 아홉 키가 달라졌는지 확인하고 달라지면 관리자라도 진단 대상을 다시 승인해야 합니다. `[]` 에서 `{}` 로 바뀐 값은 이 비교에 변경된 값이므로, JSON 칸을 비운 저장이 그 서비스의 진단 대상 승인까지 함께 해제했습니다.
- **선언한 그릇을 제출하고 다른 그릇은 칸 이름으로 거절합니다**: 이제 JSON 분기가 `resourceJSONWire` 를 지나 빈 입력(공백만 있는 입력 포함)에 선언한 그릇의 새 복제본을 제출합니다. 파싱된 값의 그릇이 선언과 다르거나 숫자·문자열·불리언 같은 맨 스칼라 또는 `null` 이면 요청을 만들지 않고 배열·객체 중 어느 형태가 필요한지 칸 이름과 함께 한국어로 안내합니다. JSON 이 아닌 글에는 기존 형식 오류 문구가 그대로 남아 두 문제를 구분할 수 있고, 유효한 입력이 만드는 요청 본문은 한 글자도 달라지지 않습니다.

서버 계약은 바꾸지 않았습니다. 두 JSON 필드의 API 형식·권한 검사·감사 기록과 일반 자원 수정의 `expected_updated_at` 비교, 409 입력 보존 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 하나이며 Go 변경은 없습니다. 이전 버전에서 이미 `{}` 로 저장된 `targets` 와 그때 해제된 진단 대상 승인은 자동으로 되돌리지 않으므로, 해당 서비스는 공격 표면을 다시 입력하고 승인을 다시 받아야 합니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.22.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 21, 0):
    features = """### 공통 자원 폼 — 일시 칸이 서버가 받을 수 있는 값만 제출합니다

- **입력한 일시가 서버 오류로 사라졌습니다**: 공통 자원 폼의 `formBody`(`web/src/resources.tsx`)는 `new Date(value).toISOString()` 결과를 검사 없이 요청 본문에 넣었습니다. ECMA-262 는 UTC 순간이 0000~9999 를 벗어나면 확장 연도(`+YYYYYY`/`-YYYYYY`)를 내놓지만, 발견 건 조치 기한·위험 수용 만료 일시, 예약 첫 실행 일시, 범위 만료 일시를 읽는 서버 경로는 모두 `time.Parse(time.RFC3339, s)` 로만 읽어 부호 없는 네 자리 연도만 받으므로 네 칸 모두 `400` 으로 거절했습니다.
- **브라우저 시간대가 수락·거절을 갈랐습니다**: 타이핑할 수 있고 사양상 유효한 `datetime-local` 값 `9999-12-31T23:59` 은 UTC 동쪽에서는 범위 안이지만 서쪽 시간대에서는 유한한 값인 채로 `+010000-01-01T04:59:00.000Z` 로 직렬화됩니다. 같은 입력이 사용자의 시간대에 따라 저장되거나 거절됐습니다.
- **번역되지 않은 브라우저 문구가 보였습니다**: ECMAScript 시간 값 범위를 벗어나는 입력에서는 `toISOString` 의 `RangeError` 가 폼을 빠져나가 영어 "Invalid time value" 로 표시됐습니다.
- **보내는 문자열을 검사합니다**: 이제 타이핑한 값이 아니라 실제로 제출하는 문자열이 네 자리 연도로 시작하는지 확인하고, 아니면 요청을 만들지 않고 해당 칸 이름과 함께 한국어로 안내합니다. 범위 안의 일시가 만드는 요청 본문은 한 글자도 달라지지 않습니다.
- **공유 벡터로 고정합니다**: `internal/app/testdata/resource-datetime.json` 이 (시간대, 입력) 쌍마다 보내는 문자열과 하나의 판정을 적고, Go 는 `validateFindingOpsResource`·`validateSchedule`·`validateScope` 로 PostgreSQL 없이 확인하며 화면 시험은 `TZ` 를 바꿔 `resourceSubmitBody` 가 `accepted` 로 표시된 문자열만 제출하는지 단언합니다.

서버 계약은 바꾸지 않았습니다. 네 필드는 그대로 네 자리 연도 RFC3339 만 받고 API 필드·권한 검사·감사 기록, 일반 자원 수정의 `expected_updated_at` 비교와 409 입력 보존 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 두 개입니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.21.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 20, 0):
    features = """### 발견 건 일괄 변경 — 조치 기한 폼이 서버가 받을 수 있는 값만 제출합니다

- **같은 변경의 담당자·상태까지 되돌려졌습니다**: 일괄 변경 폼의 `findingBulkPatch`(`web/src/finding-bulk-state.ts`)는 `new Date(...).toISOString()` 결과를 검사 없이 `due_date` 로 보냈습니다. ECMA-262 는 UTC 순간이 0000~9999 를 벗어나면 확장 연도(`+YYYYYY`/`-YYYYYY`)를 내놓지만 서버 `validateFindingOpsResource`(`internal/app/finding_ops.go`)는 `time.Parse(time.RFC3339, s)` 로만 읽어 부호 없는 네 자리 연도만 받으므로, 요청 전체가 `400` 이 되어 같은 변경에 담은 담당자·진행 상태까지 취소됐습니다.
- **브라우저 시간대가 수락·거절을 갈랐습니다**: 타이핑할 수 있고 사양상 유효한 `datetime-local` 값 `9999-12-31T23:59` 은 UTC 동쪽에서는 범위 안이지만 서쪽 시간대에서는 유한한 값인 채로 `+010000-01-01T04:59:00.000Z` 로 직렬화됩니다. 같은 입력이 사용자의 시간대에 따라 저장되거나 전체 취소됐습니다.
- **보내는 문자열을 검사합니다**: 이제 `input.due` 가 아니라 실제로 제출하는 문자열이 네 자리 연도로 시작하는지 확인하고, 아니면 요청을 만들지 않고 기한 칸 옆에 한국어로 안내합니다. 범위 안의 기한이 만드는 요청 본문은 한 글자도 달라지지 않습니다.
- **공유 벡터로 고정합니다**: `internal/app/testdata/finding-bulk-due-date.json` 이 (시간대, 입력) 쌍마다 보내는 문자열과 서버 판정을 적고, Go 는 `validateFindingBulk` 로 PostgreSQL 없이 확인하며 화면 시험은 `TZ` 를 바꿔 `accepted` 로 표시된 문자열만 제출하는지 단언합니다.

서버 계약은 바꾸지 않았습니다. `due_date` 는 그대로 네 자리 연도 RFC3339 만 받고 API 필드·권한 검사·감사 기록, 최대 100개 일괄 변경과 각 항목 `updated_at` 비교, 한 항목 충돌 시 전체 롤백 규칙도 그대로입니다. 프로덕션 변경은 화면 파일 한 개입니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.20.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 19, 0):
    features = """### 프런트엔드 회귀 검사 — npm 을 실행한 그 Node 에서 돌립니다

- **사용자 동작은 그대로**: 화면과 서버 동작, 저장되는 값, API·권한·감사 기록은 달라지지 않습니다. 검사가 조용히 0건 실행되는 일을 막는 검증 경로 수정입니다.
- **0건 실행이 성공처럼 보이던 경로**: `web/package.json` 의 `test` 스크립트가 맨 `node` 를 불렀습니다. npm 은 상위 모든 `node_modules/.bin` 을 스크립트 PATH 앞에 붙이므로 상위 디렉터리의 `node` 패키지가 `npm test` 에서만 실제 해석기를 가리고, 가려진 Node 20에서는 `node: bad option: --experimental-strip-types` 로 19개 파일이 0건 실행된 채 끝났습니다.
- **해석기를 고정합니다**: 이제 `${npm_node_execpath:-node}` 로 npm 자신의 Node 를 호출하므로 PATH 가 어떻게 바뀌어도 `npm --prefix web test` 는 `npm --prefix web ci` 를 돌린 그 해석기에서 실행됩니다.
- **플래그 제거만으로는 부족**: Node 22.18부터 불필요한 `--experimental-strip-types` 를 함께 뗐습니다. 플래그만 떼고 PATH 가 고른 Node 20으로 돌리면 그 줄에 `.ts` 타입 스트리핑이 없어 19개 파일이 모두 실패합니다.

검사 파일 목록과 단정, 서비스 코드·화면·API 필드·권한·관리자 설정은 바꾸지 않았습니다. `npm_node_execpath` 가 없는 실행기에서는 기존처럼 PATH 의 `node` 로 돌아갑니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.19.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 18, 0):
    features = """### 발견 건 일괄 변경 — 화면과 서버가 같은 문자열로 담당자 한도를 셉니다

- **사용자 동작은 그대로**: 저장되는 값, 오류 문구, 서버 API·권한·감사 기록은 달라지지 않습니다. 이미 맞는 판정이 다음 변경에서 어긋나지 않도록 고정하는 회귀 검사 릴리즈입니다.
- **같은 문자열을 셉니다**: 일괄 변경 폼의 `findingBulkPatch`(`web/src/finding-bulk-state.ts`)는 앞뒤 공백을 제거한 이름을 보내고 200바이트 한도도 그 값에서 셉니다. 서버 `validateFindingBulk`(`internal/app/finding_bulk.go`)도 받은 그 문자열을 셉니다. 표에서 복사해 공백이 붙은 이름을 화면이 미리 거절하지도, 화면이 통과시킨 이름을 서버가 `400` 으로 돌려보내지도 않습니다.
- **공유 벡터 21개**: `internal/app/testdata/finding-bulk-assignee.json` 의 허용 11개·거절 10개를 Go `TestFindingBulkAssigneeSharedVectors` 와 `web/tests/finding-bulk.test.mjs` 가 함께 읽고 같은 판정에 이르는지 확인합니다. 그 서버 검증 함수가 데이터베이스 없이 도는 첫 단위 검사이기도 합니다.
- **경계를 직접 짚습니다**: 한글 200바이트·201바이트, 이모지가 걸친 경계, 공백만 입력한 담당자 비우기, C0·DEL·C1 제어 문자와 바로 바깥의 `U+00A0` 이 들어 있습니다. Go 와 JavaScript 의 트림이 실제로 갈리는 부호 위치는 두 가지뿐이며(JavaScript 만 버리는 `U+FEFF`, Go 만 버리는 `U+0085`) 둘 다 벡터로 고정했습니다.

담당자 200바이트 한도, 제어 문자 거절, 한 번에 최대 100개, 각 항목의 현재 권한과 `updated_at` 재검사, 한 항목만 충돌해도 전체 롤백하는 규칙은 달라지지 않습니다. 벡터는 담당자 필드 하나를 다루며 조치 기한·상태 검증은 포함하지 않았습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.18.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 17, 0):
    features = """### 저장한 목록 보기 — 읽기가 버릴 조건은 저장하지 않습니다

- **저장 성공이 다음 방문까지 이어지던 차이**: 저장한 보기를 읽는 `readListPreferences` 는 조건 문자열이 8192자를 넘는 항목을 버리는데, 저장은 검색어와 각 필터 값이 500자 이하인지만 확인했습니다. 한글은 URL 인코딩에서 한 글자가 9자로 늘어나므로 검색어 500자와 필터 500자는 값 한도를 통과하고도 조건 문자열이 한도를 넘어, 저장 성공 안내를 본 사용자가 다음 방문에 그 보기를 잃었습니다.
- **읽기와 같은 한도로 거절**: 저장이 읽기와 같은 상수(`savedListQueryLimit`)를 검사하고 통과하지 못하면 조건을 줄여 달라고 안내합니다. 8192는 저장한 보기 하나를 읽을 때의 검사 한도이며 브라우저 저장소 용량 한도가 아닙니다. 저장소 용량은 원점 단위 전체 자료에 대해 측정됩니다.
- **폼 순서대로 한 가지씩**: 다섯 조건을 순수 함수 `savedViewSaveError`(`web/src/saved-list-views.ts`)에 모으고 `ListTools.save()` 는 그 함수만 호출합니다. 이름 없음 → 8개 상한 → 같은 이름 → 값 500자 초과 → 조건 길이 초과의 순서이며 이름 칸이 고칠 수 있는 오류에만 초점을 되돌립니다.
- **조건마다 검사 고정**: `saved-list-views.test.mjs` 가 한글 500자 조건이 실제로 한도를 넘고 읽기가 그 보기를 버리는 것을 확인한 뒤 같은 입력의 저장이 거절되는 것을, 읽기가 보존하는 조건은 저장되고 복원되는 것을 확인합니다. 조건 하나를 지우면 검사가 실패합니다.

사용자·메뉴별 최대 8개, 값 500자 한도와 자르기, 허용된 목록 조건만 보관하고 상세 ID·임의 URL 매개변수·폼 초안·비밀값을 저장하지 않는 규칙은 달라지지 않습니다. 이미 저장된 보기를 다시 해석하지 않으며 서버 API·권한·감사 기록과 관리자 설정 항목은 추가하거나 바꾸지 않았습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.17.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 16, 0):
    features = """### 목록 주소 복사 — 저장소 한도가 아니라 보고 있는 목록

- **복사한 주소가 다른 결과를 열던 차이**: 목록 도구의 **목록 주소 복사**는 주소를 만드는 `listSharePath` 에서 저장한 보기와 같은 `savedListQuery` 를 그대로 썼습니다. 그 함수의 500 코드 단위 자르기는 `localStorage` 보관을 위한 한도이므로, 검색어나 필터 값이 500자를 넘으면 주소의 `q`·`f_*` 가 조용히 잘려 받는 사람이 보낸 사람과 **다른 결과 집합**을 열었습니다.
- **자르기를 명시적으로 선택**: `savedListQuery` 가 자르기 여부를 인자로 받고 기본값은 기존 저장소 한도입니다. 주소 복사 경로만 이를 끄므로 복사한 주소는 주소창이 담는 길이만큼 검색·필터 텍스트를 온전히 담습니다.
- **저장한 보기는 그대로**: 사용자·메뉴별 최대 8개, 500자 한도, 허용된 목록 조건만 보관하고 상세 ID·임의 URL 매개변수·폼 초안·비밀값을 저장하지 않는 규칙과 저장·복원이 같은 조건 문자열을 비교하는 동작은 달라지지 않습니다.
- **서러게이트 쌍까지 검사**: `convenience.test.mjs` 가 499자 뒤에 `🚀` 와 100자를 더한 입력으로 주소의 `q`·`f_service_id` 가 원문과 같은 길이·같은 값이고 대체 문자가 생기지 않는 것을, 같은 입력의 저장한 보기 경로는 여전히 잘리는 것을 함께 확인합니다.

주소에 담기는 항목은 늘어나지 않습니다. 이번 변경은 허용된 값의 **길이**만 되돌린 것이며 임의 매개변수를 통과시키지 않습니다. 받는 사람에게 보이는 결과는 언제나 그 사람의 현재 권한으로 서버가 판단하고, 서버 API·권한·감사 기록과 관리자 설정 항목은 추가하거나 바꾸지 않았습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.16.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 15, 0):
    features = """### 방문 추적 허용 원점 — 화면 제안과 서버 계약의 일치

- **제안한 원점이 저장에서 거절되던 차이**: **보안 정책에서 차단된 출처** 패널의 "허용 목록에 추가" 와 설정 화면의 사전 검사는 지금까지 브라우저 URL 파서로 원점을 읽었습니다. 파서는 `http://0177.0.0.1`·`http://0x7f.1`·`http://2130706433` 같은 옛 IPv4 별칭을 정식 주소로 접어 버리고, 숫자 최상위 라벨·퍼센트 인코딩 호스트·라벨 63바이트·호스트 253바이트·포트 1~65535 범위를 검사하지 않았습니다. 서버의 `trackingOrigin` 은 별칭이 앱 원점 거부를 우회하지 못하도록 이를 거절하므로 버튼이 제안한 원점이 `PUT` 에서 거절될 수 있었습니다.
- **같은 규칙을 원문에 적용**: 이제 `normalizeTrackingOrigin` 이 서버 규칙을 원문 텍스트에 직접 적용하고, 차단 출처 제안과 초안 검사가 모두 이 함수를 거칩니다. 허용 주소의 1,536바이트 합계도 서버처럼 **중복 제거 후 원점마다 `len+1`** 로 셉니다.
- **`xn--` 라벨을 화면에서 직접 해독**: 이미 ASCII 인 ACE 라벨은 URL 파서마다 처리가 달라 화면과 서버의 판정이 갈렸습니다. 이제 서버가 `idna.Lookup.ToASCII` 로 하는 것과 같게 RFC 3492 해독을 화면에서 수행하고 그 결과만 파서로 다시 인코딩하며, 해독할 수 없거나 평범한 ASCII 로 풀리는 라벨은 런타임과 무관하게 거절합니다.
- **한 파일로 두 구현을 고정**: `internal/app/testdata/tracking-origins.json` 의 공유 벡터 105개(원점 78·차단 출처 22·초안 5)를 Go 의 `TestTrackingOriginVectors` 와 프런트엔드의 `tracking-state.test.mjs` 가 함께 읽습니다.

서버 파서, 이미 저장된 허용 목록, 추적 revision·미리보기 5분 1회·격리 iframe 과 고정 path·title 수집 범위는 달라지지 않습니다. 방문 추적은 기본 꺼짐이며 관리자 설정 항목·API 계약·권한은 추가하거나 바꾸지 않았습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.15.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 14, 0):
    features = """### 보고서 내보내기 CSV — 목록 CSV와 같은 수식 방지 판정

- **앞 공백에 가려진 수식**: `GET /api/reports/export?format=csv` 는 지금까지 값의 **첫 글자만** 검사했기 때문에 ` =1+1` 처럼 공백·제어문자가 앞에 붙은 제목·출처·CVE 를 그대로 내보냈습니다. 화면의 목록 CSV 내려받기는 이미 앞 공백을 건너뛰고 검사하고 있어 같은 값의 결과가 서버와 화면에서 달랐습니다.
- **같은 규칙으로 정렬**: 이제 서버도 앞쪽 공백류를 건너뛴 뒤 `=`·`+`·`-`·`@` 를 찾으면 `'` 를 붙입니다. 값이 탭·CR·LF 로 시작할 때 `'` 를 붙이던 기존 동작은 그대로입니다.
- **공백의 정의를 문서가 아니라 자료로 고정**: 두 구현이 `internal/app/testdata/csv-safety.json` 의 공유 벡터 83개를 함께 읽습니다. ECMAScript `\\s` 와 C0 제어문자를 공백으로 보므로 `FEFF` 는 건너뛰고 `0085`·`180E`·`200B` 는 건너뛰지 않습니다.
- **저장된 값은 그대로**: 붙는 `'` 는 CSV 내보내기에만 적용합니다. DB 의 원래 값과 `format=json` 내보내기, 화면 표시는 달라지지 않으며 접근 범위·감사 기록(`reports.export`)도 기존과 같습니다.

스프레드시트 애플리케이션의 수식 실행을 막기 위한 내보내기 측 방어이며, 값 자체를 검사하거나 거부하지 않습니다. 관리자 설정 항목·API 계약·권한은 추가하거나 바꾸지 않았습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.14.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 13, 0):
    features = """### 다른 서비스로 보내기 — 사용자당 미사용 표 20개 상한

- **표 테이블 무한 증가 차단**: `POST /api/v1/handoff/claims` 는 표 하나마다 암호화한 실행 보고서 전체를 함께 저장하는데 지금까지는 만료 행만 정리했습니다. 이제 만료 정리 직후 **같은 트랜잭션에서** 그 사용자의 아직 쓰지 않은(만료 전·미수령) 표를 세고, 20개 이상이면 표를 만들지 않습니다.
- **거절의 모양**: 한도를 넘은 호출은 `429` 와 "발급했지만 아직 쓰지 않은 표가 너무 많습니다. 잠시 후 다시 시도하세요" 로 답하며 `handoff_claims` 행도 감사 기록(`agent.handoff`)도 남기지 않습니다.
- **자리가 다시 생기는 조건**: 상한은 사용자별이므로 다른 사람의 발급에는 영향이 없고, 받는 쪽이 표를 받아 가거나 5분 TTL 이 지나면 곧바로 한 자리가 비웁니다.
- **화면은 그대로**: 실행 상세의 **실행 보고서 → 다른 서비스로 보내기**는 한 번 누를 때 표 하나를 만들어 바로 넘기므로 평소 사용에서는 상한에 닿지 않습니다. 허용 목록·기본 꺼짐·표의 1회·5분·SHA-256 다이제스트 저장과 MCP · SSO 연결은 v1.12.0과 같습니다.

상한은 근사값입니다. 동시에 들어온 두 호출이 같은 수를 읽어 둘 다 통과할 수 있으며, 목적은 정확한 개수 제한이 아니라 반복 호출이 표 테이블을 채우지 못하게 하는 것입니다. 관리자 설정 항목은 추가하지 않았고 값은 코드의 20으로 고정입니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[다른 서비스로 보내기 운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.13.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 12, 0):
    features = """### MCP · SSO 연결 — /mcp 를 OAuth 2.1 리소스 서버로

- **키 없이 SSO 로 연결**: 관리자가 **서비스 설정 → MCP · SSO 연결**(`mcp.oauth.enabled/resource/audience/scopes`, 기본 꺼짐)을 켜면 MCP 클라이언트(Claude, Cursor 등)에 `/mcp` 주소 하나만 넣어도 클라이언트가 스스로 Keycloak 로그인을 거쳐 액세스 토큰을 받아 옵니다. 개인 키 페이지의 MCP 카드에 "키 없이 SSO 로 연결하기" 안내가 보이며 개인 키 체계는 그대로입니다.
- **Hunter 는 리소스 서버**: 토큰을 발급하지 않고(`/authorize`·`/token`·동적 클라이언트 등록 없음) `/.well-known/oauth-protected-resource(/mcp)` 메타데이터(RFC 9728, 맨 JSON, CORS `*`, 꺼지면 404)와 `/mcp` 401 의 `WWW-Authenticate: Bearer realm="hunter", resource_metadata="…"` 로 클라이언트를 Keycloak 으로 보냅니다. 이 헤더는 MCP 경로에만 붙고 REST·GraphQL·관리 API 는 지금처럼 키·세션만 받습니다. 리소스 식별자는 비우면 서비스 외부 접근 주소 + `/mcp` 이며 요청 `Host` 헤더는 쓰지 않습니다.
- **토큰 검사와 계정 매핑**: 같은 Bearer 헤더에서 `hnt_` 접두사는 키, JWT 모양은 SSO 토큰으로 가르고, `typ=ID`·`HS*`/`none` 은 서명키 요청 전에 거부한 뒤 서명·`iss`·`exp`·`nbf`·`cnf`·`sub`·대상(`aud` 의 리소스 식별자 또는 `aud`/`azp` 의 허용 대상·웹 Client ID)을 검사합니다. 계정은 웹 로그인과 같은 `iss|sub` 해시로 **이미 웹 로그인한 활성 계정**만 찾으며 계정 생성·사용자명 대체 조회·토큰 role 승격은 없습니다. 권한은 `mcp.oauth.scopes`(기본 읽기 3개) ∩ 역할 권한이고 교집합이 비면 거부합니다.
- **운영 안내**: 켤 때 OIDC 꺼짐·Issuer 없음·빈 범위는 400 으로 거부하고, 켠 뒤 전제가 사라지면 꺼진 것처럼 동작하며 `mcp oauth switched on but inactive` 로그를 남깁니다. 거부는 401 본문의 메시지(다른 대상이면 본 `aud`/`azp` 와 적을 값)와 서버 로그 `mcp sso token rejected cause=…` 로 남기고, SSO 토큰으로 호출한 도구는 감사 기록에 `auth: sso` 로 표시됩니다. 관리자 가이드 §15.6 에 Keycloak 클라이언트·Audience 매퍼 표와 curl 확인 절차가 있습니다.
- **기존 보호 유지**: 다른 서비스로 보내기 허용 목록, OIDC 자동 진입 기본 꺼짐, state·nonce·PKCE·서명 토큰·현재 역할 검사, 방문 추적의 격리 미리보기와 CSP 차단 출처 패널은 v1.11.0과 같습니다.

Hunter 는 introspection 을 하지 않으므로 Keycloak 로그아웃·사용자 비활성화 뒤에도 이미 발급된 토큰은 만료까지 살며, 급하면 Hunter 사용자를 비활성화합니다(비활성 계정 토큰은 즉시 거부). 실제 Keycloak·실제 MCP 클라이언트로 URL 만 넣어 연결하는 검증은 가짜 IdP 가 서명한 Keycloak 26 모양 토큰으로 대체했습니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[MCP·SSO 연결 운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 키 없이 연결하기 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.12.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 11, 0):
    features = """### 실행 보고서 다른 서비스로 보내기와 추적 프레임 CSP 차단 출처 허용

- **다른 서비스로 보내기**: 실행 상세의 실행 보고서 메뉴에서 관리자가 허용한 사내 서비스 이름을 고르면 파일을 내려받지 않고 새 창에서 그 서비스가 Markdown 보고서를 직접 받아 갑니다. 사내 문서 넘기기 표준(HANDOFF-STANDARD)의 보내는 쪽 `markdown` 규격을 따르며 받는 쪽은 만들지 않았습니다.
- **5분·1회용 표**: `POST /api/v1/handoff/claims`는 지금 이 실행을 읽을 수 있는 사용자에게만 256비트 난수 표를 발급하고(다운로드와 같은 권한 검사, 읽을 수 없는 실행·미설정 404), `GET /api/v1/handoff/claims/{claim}`은 로그인 없이 `text/markdown` 첨부로 한 번만 내주며 사용됨·만료·미발급을 구별 없이 404로 답합니다. 본문은 암호화 저장하고 표는 SHA-256 다이제스트만 남기며 감사 기록에는 실행 ID·바이트 수만 적습니다.
- **허용 목록 기본 비어 있음**: 서비스 설정의 **다른 서비스로 보내기** 탭(`handoff.targets`)에서 이름·오리진·받는 형식을 최대 20개 관리합니다. 목록이 비어 있으면 메뉴 항목이 없고 발급도 404로 거절하므로 새 설치는 달라지지 않습니다. markdown 을 받지 않는 서비스는 메뉴에 오르지 않습니다.
- **보안 정책에서 차단된 출처**: 방문 추적 격리 프레임의 CSP 차단(securitypolicyviolation) 출처·지시어를 로그인된 부모 화면이 서버에 대신 신고하고, 관리자는 방문 추적 설정의 새 패널에서 조회·지우기·허용 원점에 추가한 뒤 저장합니다. 인스턴스 메모리 100개 고리 버퍼에 원점·지시어만 보관하고 경로·쿼리·inline·eval·data:·blob: 은 기록하지 않으며 앱 자체 CSP는 완화하지 않습니다.
- **기존 보호 유지**: OIDC 자동 진입 기본 꺼짐, state·nonce·PKCE·서명 토큰·현재 역할 검사, 방문 추적의 격리 미리보기와 revision 충돌 보호는 v1.10.0과 같습니다.

실제 사내 받는 서비스와의 왕복은 route 스텁으로만 확인했으며 조직에서 `origin/handoff?source=…&claim=…` 진입 화면을 준비해야 합니다. 차단 출처 버퍼는 서버 재시작 시 사라지고 추적이 꺼진 동안 비관리자 신고는 거절합니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[보내기 허용 목록·추적 운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 보고서 보내기 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.11.0.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 10, 0):
    features = """### 자동 SSO 진입의 명시적 사용 설정과 저장소 차단 시 억제

- **자동 진입 기본 꺼짐**: OIDC `auto_login`의 기본값이 꺼짐입니다. 설정 키가 없거나 불리언이 아니면 꺼진 것으로 취급해 기본 설치에서는 prompt=none 요청을 보내지 않습니다. 서버 기본 설정·관리자 설정 화면·OpenAPI 계약이 같은 기본값을 사용합니다.
- **평범한 로그인 복귀**: 자동 진입이 꺼진 상태의 `?mode=auto` 요청은 IdP에 접속하지 않고 로그인 화면으로 돌아갑니다. 관리자가 켜면 기존과 같이 prompt=none으로 사내 인증 세션을 확인합니다.
- **저장소 차단 시 재시도 억제**: sessionStorage를 읽을 수 없으면 브라우저는 자동 시도를 이미 한 것으로 간주해 사생활 보호 모드에서 리디렉션을 반복하지 않습니다.
- **기존 보호 유지**: state·nonce·PKCE·서명 토큰·현재 역할 검사, 자동 시도10분·명시 로그아웃24시간 억제, `/login?local=1` 복구와 `return_to` 검증은 v1.9.0과 같습니다. 관리자 격리 방문 추적은 변경이 없습니다.

v1.9.0에서 자동 진입을 사용하던 조직은 업그레이드 후 **관리자 → 서비스 설정 → OIDC**에서 자동 진입을 다시 켜야 합니다. 기존 설정에 `auto_login: true`가 저장되어 있으면 그대로 유지됩니다. 실제 운영 ReSSO 계정 연동 검증은 미수행이며 사내 환경에서 OIDC Discovery·Code·PKCE·prompt=none 지원을 확인해야 합니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[SSO 운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 로그인·복구 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [공식 근거와 적용 범위](https://github.com/hkjang/hunter/blob/main/docs/research-sso-tracking.md) · [릴리즈 노트](https://github.com/hkjang/hunter/blob/main/docs/release-v1.10.0.md)

"""
elif version >= (1, 9, 0):
    features = """### 기존 SSO 세션 자동 진입과 관리자 방문 추적

- **로그인 화면을 거치지 않는 업무 복귀**: 유효한 Hunter 세션은 바로 내부 목적지로 이동하고, OIDC 자동 진입을 켜면 prompt=none으로 사내 인증 세션을 확인합니다. 원래 메뉴·검색 조건·해시를 안전한 내부 주소로 보존합니다.
- **명시 로그인과 복구**: 인증·동의가 필요하면 로컬 또는 명시 SSO 로그인으로 돌아갑니다. 자동 시도10분·명시 로그아웃24시간 재시도 억제와 /login?local=1 복구 경로로 로그인 반복을 줄입니다. 기존 state·nonce·PKCE·서명 토큰·현재 역할 검사를 유지합니다.
- **관리자 방문 추적**: 서비스 설정에서 공개 JavaScript32KiB 또는 script태그10개와 정확한 허용 원점10개를 관리합니다. 기본 비활성이며 관리자 브라우저 세션·암호화 저장·숫자revision 충돌 보호를 적용합니다.
- **저장 전 격리 미리보기**: 관리자별5분·1회 초안을 별도 sandbox에서 실행합니다. 일반 메뉴의 고정 경로·제목만 전달하고 로그인·관리자·개인화 화면, 실제 자료ID·사용자·검색어·본문은 페이지 이벤트에서 제외합니다. 추적 오류는 일반 업무와 분리합니다.

[공식 ReSSO](https://github.com/hkjang/ReSSO)의 OIDC·prompt=none 지원 소스를 확인했으며 실제 운영 계정 연동 검증은 미수행입니다. 표준 OIDC Discovery·Code·PKCE·prompt=none 지원 여부를 확인해야 합니다. IdP 주소 자체에 접속할 수 없어 callback이 없으면 Hunter 로컬 복구 주소를 직접 엽니다.

방문 추적의 준비 완료는 수집 서버의 실제 접수 보장이 아닙니다. 쿠키·localStorage·부모 DOM·eval·iframe에 의존하는 SDK는 이벤트 어댑터가 필요하며 HTTP의 IP·User-Agent 정보는 수집기에서 관측할 수 있습니다. 로컬 모의 OIDC·수집기 검증과 실제 운영 계정·통계 수신 검증을 구분합니다.

네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 배포 조건을 유지합니다. 최종 게시 커밋의 CI·공개 파일 검증 결과는 실제 완료 후 이 본문에 별도로 기록합니다.

[SSO·방문 추적 운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 로그인·복구 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [공식 근거와 적용 범위](https://github.com/hkjang/hunter/blob/main/docs/research-sso-tracking.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 8, 0):
    features = """### 에이전트 선택 연동·복구와 실행 보고서

- **모델 네이티브 연결**: OpenAI 호환·Anthropic Messages·Gemini·Ollama의 실제 스트리밍 규격을 사용하고 역할별 순서·우선순위·컨텍스트·출력·연속 실패 보호를 설정합니다. 실패한 응답 조각은 사용자 출력과 도구 실행 전에 폐기합니다.
- **검색·지식 메모리**: 검색 공급자 여섯 종류와 임베딩·Graphiti를 선택 연결합니다. 검색 장애에는 내부 근거를 사용하고 원격 그래프 문장 대신 현재 허용된 로컬 기억만 반환합니다. pgvector는 이미 설치된 경우 사용하며 없으면 로컬 검색으로 복귀합니다.
- **명시적 개입·재개**: 추가 입력, 안전 경계의 일시 중지, 입력·모델 연결 대기 후 같은 실행 ID의 체크포인트 재개를 제공합니다. 원래 키·서비스·범위·정책과 누적 모델·도구·활성 시간 한도를 다시 검사합니다. 종료·프로세스 강제 종료를 자동 재실행하지 않습니다.
- **고정 격리 진단**: 관리자 mTLS Docker 서버에서 같은 Hunter 이미지의 고정 HEAD·TLS 인증서·TCP 연결 프로브를 실행합니다. 현재 승인·망·정책과 digest를 검사하고 생성 이후 결과가 불명인 작업을 자동 중복 실행하지 않습니다.
- **비동기 관측**: 마스킹한 메타데이터를 암호화 큐에서 OTLP HTTP·Langfuse로 전달합니다. 유한 재시도·대체 수집기를 설정하며 수집 장애로 업무 응답을 중단하지 않습니다. 프롬프트·도구 결과·증거를 보내는 전체 로그 기능이 아닙니다.
- **조회와 공유**: 현재 사용자·키·서비스 범위를 적용한 읽기 전용 GraphQL과 실행별 MD·HTML·한국어 PDF 다운로드를 제공합니다. 진행·대기·실패 상태도 현재 상태 그대로 보고하며 PDF 폰트는 이미지에 포함합니다.

새 **에이전트 통합 연동**의 외부 연동은 기본 비활성입니다. 일반 PostgreSQL, 네 환경변수와 서비스 Docker 이미지 하나로 기본 운영하며 선택 서버는 관리자 설정으로 연결합니다. 원본 PentAGI 312파일을 보존하고 Hunter 도구에 비신뢰 참고 검색을 추가했습니다. 원본 외부 스택·임의 셸·공격 도구 번들·자동 이미지 다운로드는 제공 범위가 아닙니다.

연동 검증은 내부 모의 API·모델 및 합성 대상의 프로토콜·권한·실패 복구를 확인합니다. 실제 공급 계정·검색/모델 품질·운영 대상 탐지율 검증과 구분합니다. 공개 릴리즈 파일의 검증 결과는 실제 다운로드 후 별도로 기록합니다.

[관리자 선택 연동 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 재개·보고서 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [공식 규격과 적용 범위](https://github.com/hkjang/hunter/blob/main/docs/research-agent-platform.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 7, 0):
    features = """### 담당자와 외부 업무를 연결하는 자동화

- **담당자·조직·당직 수신자**: 관리자 확인 연락처와 현재 사용자·서비스 접근 권한을 대조해 수신자를 계산합니다. 고정 수신자와 함께 사용할 수 있으며 개인에게 연결된 알림은 **내 업무 알림**에서 확인합니다.
- **알림 묶음·발송 한도**: 같은 조건의 사건을 모으고 수신자별 한도와 긴급 예외를 적용합니다.
- **영업일 기한 예고**: 조직 시간대·업무 요일·휴일을 반영해 유효 기한이 다가오는 발견 건을 안내합니다.
- **업무 확인·미확인 대응**: 지정 수신자가 알림을 확인하고 기한 이후 미확인 사건을 별도 규칙으로 전달합니다. 업무 확인은 팀장 승인이나 발견 건 해결을 변경하지 않습니다.
- **조직 주간 요약**: 신규·미조치·기한 경과와 기간 내 갱신된 현재 해결 상태를 요약합니다. 동적 사용자는 현재 접근 범위, 관리자 지정 고정 주소는 해당 조직의 집계 범위를 사용합니다.
- **전달 결과·대체 채널·보호**: 사내 게이트웨이의 조회·서명 콜백을 연결하고 실패가 확정된 경우에만 한 단계 대체 채널을 요청합니다. 발송 간격과 오류 누적에 따른 일시 중단을 설정합니다.
- **변경 영향별 검사 선택**: 서명된 실제 경로·API·구성요소·권한 변경 목록과 서비스별 규칙을 대조해 일치한 검사만 현재 정책으로 요청합니다. 미리보기에서는 진단을 만들지 않습니다.
- **ITSM 동기화**: 외부 티켓의 담당자·기한·상태를 조회·서명 콜백으로 반영하고 로컬 수정 충돌을 보존합니다. 명시 적용도 확인했던 로컬·외부 버전과 내용을 다시 검사합니다.
- **발송 없는 모의 검사**: 보관된 사건을 현재 규칙에 대조해 예상 대상 수와 제외 사유를 확인합니다.
- **본문 보존·파기**: 적격 종결 알림의 본문·수신 정보·시도 상세를 정리합니다. 업무 미확인·진행 중·결과 불명·보존 고정 건과 중복 식별 기록은 보호합니다.

새 **자동화 관리**는 기본 비활성이며 필요한 기능만 설정해 켭니다. 관리자 변경과 실행에는 현재 권한·키·서비스 범위를 재검사합니다. 기존 고정 수신 규칙, 네 환경변수, 일반 PostgreSQL과 서비스 Docker 이미지 하나의 오프라인 배포를 유지합니다.

게이트웨이 접수, 공급자 전달 결과, 개인 업무 확인, 팀장 승인과 취약점 해결은 별개입니다. 결과 불명·조회 불가·충돌을 실패로 추정해 자동 재발송하지 않으며 receipt가 있는 같은 전달 ID의 재시도도 막습니다. 설정 변경으로 과거 receipt를 새 규격으로 재해석하지 않습니다. 외부 티켓 완료만으로 발견 건을 해결하지 않으며 명시적인 배포 확인이 있을 때 현재 정책이 허용한 재검증만 요청합니다.

Hunter HMAC 콜백은 사내 게이트웨이 계약이며 Git·문자·알림톡 공급자의 원래 서명과 본문을 그대로 받는 범용 호환 API는 아닙니다. 연결 검증에는 로컬 모의 SMTP·API와 합성 자료를 사용하며 실제 공급 계정·외부 수신 도달·알림톡 템플릿 승인은 별도 확인 대상입니다.

[자동화 설정·복구 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html#13-10-자동화-관리-시작하기) · [내 업무 알림](https://hkjang.github.io/hunter/guides/user-guide.html#12-6-내-업무-알림과-확인) · [공식 설계 근거](https://github.com/hkjang/hunter/blob/main/docs/research-automation.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

"""
elif version >= (1, 6, 0):
    features = """### 사내 알림 연동과 발송 관리

- **관리자 알림 센터**: SMTP 메일, 문자, 카카오톡, 일반 HTTP 채널을 여러 개 등록하고 이벤트·심각도·서비스·조직별 규칙과 수신자를 설정합니다. 채널과 규칙은 사용 설정 후 자동 발송을 시작합니다.
- **유연한 사내 API 연동**: JSON·폼 본문, 안전한 변수 치환, Bearer·Basic·사용자 지정 인증 헤더·NCP HMAC 서명, 응답 성공 조건·접수 ID 경로를 설정합니다. SMTP는 필수 STARTTLS·TLS와 사내 무인증 릴레이, PLAIN·LOGIN 인증 및 내부 CA를 지원합니다.
- **DB 발송 대기열**: 이벤트를 업무 변경과 같은 트랜잭션으로 기록하고 수신자별 암호화 발송 대기를 만듭니다. 안전하게 재시도할 수 있는 오류에는 횟수 제한과 지연을 적용하며, 접수 여부가 불명확한 응답·워커 중단은 결과 확인 필요 상태로 남깁니다.
- **운영 편의**: 저장한 채널의 시험 발송, 메시지 미리보기, 발송 이력 검색·필터·상세·취소와 명시적 재시도를 제공합니다. 채널·규칙 편집 충돌을 감지하고 변경 전 대기 건은 취소합니다. 운영 점검에서도 실패·결과 불명·지연을 확인합니다.
- **화면 복구와 모바일 사용성**: 알림 목록 도구의 작은 화면 배치와 확인창 겹침을 보완하고, 최초 설정 응답이 늦어도 승인 메뉴의 직접 진입·새로고침 경로를 유지합니다.

API 성공·SMTP 접수는 단말 도달이나 읽음 확인을 뜻하지 않습니다. 문자 발신번호와 카카오 알림톡 발신프로필·승인 템플릿 및 공급자별 규격은 사내 중계 시스템 또는 계약한 공급자에서 준비합니다. 폐쇄망에서는 승인된 사내 SMTP·메시지 중계 서버에 연결합니다.

[설정·템플릿·운영 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [공식 연동 조사 근거](https://github.com/hkjang/hunter/blob/main/docs/research-notifications.md)

네 환경변수, PostgreSQL, 오프라인 UI 자산 및 서비스 Docker 이미지 하나로 운영합니다. 실제 수신자 대상의 임의 시험 발송은 수행하지 않았으며 연결 검증은 로컬 모의 SMTP·API를 사용합니다.

"""
elif version >= (1, 5, 0):
    features = """### 반복 업무 편의와 입력·자료 보호

- **발견 건 일괄 변경**: 현재 페이지에서 최대 100개를 선택해 담당자·수동 기한·허용된 진행 상태를 함께 변경합니다. 현재 권한과 조회 버전을 재확인하며 한 항목이라도 충돌하면 전체 취소합니다. 해결·오탐·위험 수용은 개별 검토를 유지합니다.
- **조회 결과 활용**: 현재 검색·필터·정렬을 적용한 일반 목록을 CSV로 내보내고 목록 주소와 상세 ID·링크를 복사합니다. 조치함 CSV는 현재 서버 페이지 범위입니다. CSV의 수식 시작 문자를 텍스트로 처리합니다.
- **입력 보호와 충돌 안내**: 일반 자원 수정에 조회 버전을 전달하고 충돌 시 입력을 유지합니다. 최신 자료를 확인한 뒤 명시적으로 재작성하며, 폼 닫기와 작성 중 댓글 이동에 확인을 제공합니다. 설정·사용자·워커의 별도 API까지 같은 버전 비교를 적용하는 기능은 아닙니다.
- **탭별 탐색과 새 캠페인**: SBOM·캠페인의 탭별 검색·정렬·페이지·비교 기준과 저장 보기를 분리합니다. 소프트웨어의 서비스명 검색·서비스 필터 복원과 한글 문서명의 UTF-8 제한 안내를 개선했습니다. 기존 캠페인은 현재 대상 접근을 다시 확인해 새 초안으로 복사하고, 검토 후 별도로 시작합니다.
- **응답·증거 처리 보완**: 비정상 서버 응답과 화면 오류에 한국어 복구 안내를 제공하고 오래된 조회 요청을 취소합니다. 구조형 증거의 잘못된 입력을 거부하고, 과거 구조형 증거는 같은 암호화 키 검증 후 서버 시작 전에 배치로 마스킹·암호화합니다. 과거 백업·별도 복제본은 소급 정리하지 않습니다.

[사용자 가이드](https://hkjang.github.io/hunter/guides/user-guide.html) · [업그레이드·API·복구 안내](https://hkjang.github.io/hunter/guides/admin-guide.html) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

기존 SLA·KEV/EPSS·SBOM·캠페인, PentAGI 원본 312파일과 일곱 에이전트 도구의 통제, 네 환경변수·단일 서비스 이미지 구성을 유지합니다. CSV·공유·일괄 변경은 현재 권한이나 진단 승인 범위를 확대하지 않습니다.

"""
elif version >= (1, 4, 0):
    features = """### 보안 조치와 소프트웨어 구성 관리

- **조치함·SLA**: 접근 가능한 전체 미조치 발견 건을 서버에서 검색·집계·페이지 처리합니다. 기한 초과·임박·담당자 미지정을 찾고 우선순위 산정 근거를 확인합니다. 관리자가 SLA를 켜면 생성일과 심각도별 기한을 적용하며 개별 기한이 우선합니다.
- **오프라인 위협 정보**: 관리자 화면에서 KEV JSON·EPSS CSV를 반입합니다. 기준일·SHA256·노후화를 표시하고, 잘못된 파일이나 이전 기준일은 기존 자료를 덮어쓰지 않습니다. 정보 부재를 0점으로 해석하지 않습니다.
- **SBOM 인벤토리**: CycloneDX 1.4–1.6·SPDX 2.2/2.3 JSON의 구성요소와 의존관계를 반입하고 버전·라이선스 변경과 영향 서비스를 찾습니다. 미기재·복합식·관리자 지정 라이선스는 검토 대상으로 표시합니다.
- **공통 원인·활동 기록**: 동일 CVE와 구성요소의 발견 건을 후보로 묶어 탐색하되 각 서비스의 상태를 유지합니다. 댓글은 마스킹 후 암호화하고 기존 관찰·검증·선별 감사 기록을 함께 봅니다.
- **진단 캠페인**: 최대 20개 대상의 진단을 정책 검사 후 한 번에 생성합니다. 중복 시작은 기존 실행을 반환합니다. 같은 조건으로 완료한 내장 진단의 결과를 비교하며 미관측 항목은 자동 해결하지 않습니다. 외부 수입·불완전 실행·조건이 다른 실행은 비교 불가 사유를 표시합니다.
- **운영 점검·연계 API**: 관리자에게 DB·대기열·워커·긴급 중지·자료 갱신 상태를 제공합니다. 새 REST API와 권한별 MCP 조회 도구 4개를 추가했습니다.

[GitHub·공식 문서 조사와 채택 범위](https://github.com/hkjang/hunter/blob/main/docs/research-v140.md) · [검증 기록](https://github.com/hkjang/hunter/blob/main/docs/validation.md)

새 기능은 Hunter 자체 구현입니다. PentAGI 원본 312파일과 기존 일곱 에이전트 도구의 실행 통제, 네 환경변수·단일 서비스 이미지·오프라인 자산 구성을 유지합니다. SBOM 반입은 취약점 DB 조회나 진단 자동 실행을 뜻하지 않으며 라이선스 표시는 법적 판정이 아닙니다.

"""
elif version >= (1, 3, 0):
    features = """### 일상 업무를 위한 화면 사용성 개선

- 목록 위에서 검색 결과 수와 적용 조건을 확인하고 검색어·필터를 하나씩 해제합니다. 자주 쓰는 검색·필터·정렬·표시 수는 사용자·메뉴별로 이 브라우저에 최대 8개 저장하고 첫 페이지부터 다시 불러옵니다.
- 긴 표의 열 제목과 데스크톱 첫 열을 고정합니다. 행 간격은 글자 크기를 유지한 채 조절하고, 필요하면 표 전체를 펼쳐 페이지 스크롤로 확인합니다. 모바일에서는 첫 열을 고정하지 않아 좁은 화면을 가리지 않습니다.
- 관리자 설정과 개인화 화면에서 입력 오류·저장 실패를 지속적으로 안내하고 오류 필드로 이동합니다. 설정 그룹을 저장해도 다른 그룹의 작성 내용은 유지하며, 탭 이동 시 작성 내용 유지·저장·취소를 선택합니다.
- 키보드의 본문 바로가기, 화면 이동 후 제목 초점, 모바일 메뉴의 초점 순환·Escape 닫기·버튼 복귀를 개선합니다. 닫힌 모바일 메뉴의 항목에는 초점이 들어가지 않습니다.

[UX 조사 근거와 검증 범위](https://github.com/hkjang/hunter/blob/main/docs/ux-research.md)를 공개합니다. 브라우저에 저장한 보기는 다른 기기와 동기화되지 않으며, 검색·정렬은 현재 API 조회 범위 안에서 동작합니다. 기존 네 환경변수·단일 서비스 이미지·오프라인 자산 구성을 유지합니다.

"""
elif version >= (1, 2, 0):
    features = """### 목록 탐색과 빠른 이동 개선

- 서비스·발견 건·진단·관리 목록에 열 정렬, 한국어·여러 단어 검색, 구분별 필터, 페이지당 10/25/50/100개 표시와 페이지 이동을 제공합니다.
- 검색·정렬·필터·페이지를 주소에 보존합니다. 새로고침과 뒤로 가기, 로그인 복귀 시 기존 목록 조건을 유지하고, 조건 초기화로 기본 목록에 돌아갑니다.
- 리소스 상세에서 이전·다음 항목으로 이동하며, 에이전트 상세에서도 원래 목록의 검색 조건으로 돌아갑니다.
- **Ctrl+K / ⌘K** 빠른 이동에서 한국어·영어 별칭·한글 초성으로 메뉴를 찾고 방향키와 Enter로 이동합니다. 사용자별 즐겨찾기와 최근 방문 메뉴는 해당 브라우저에 저장하며 현재 접근 권한을 적용합니다.
- 사용자 역할·조직·상태, 개인 키 권한·만료 상태, 감사 기록 기간·작업·수행자, 에이전트 상태·서비스 필터를 제공합니다.

목록 검색·정렬은 API가 반환한 자료에 적용합니다. 조회 상한에 도달한 경우 화면 하단에 검색 범위를 표시합니다. 기존 네 환경변수·단일 서비스 이미지·오프라인 자산 구성을 유지합니다.

"""
elif version >= (1, 1, 0):
    features = """### 에이전트 진단

- 서비스별 목표를 입력하면 내장한 PentAGI 원본 코어가 작업을 나누고 역할 위임·실행·재시도·결과 검토를 진행합니다.
- 새 에이전트 화면에서 목표와 결과, 실시간 응답, 도구 호출, 실행 기록과 연결된 진단을 확인합니다. 실행을 중지하거나 같은 목표로 새 실행을 만들 수 있습니다.
- 실제 행위는 서비스·발견 건 조회, 진단 요청·결과 조회, 후보 등록, 기억 저장·검색의 **일곱 Hunter 도구**로 제한합니다. 기존 권한·서비스 승인·유효 범위·검토 정책을 적용합니다.
- **관리자 → 서비스 설정 → 에이전트 진단**에서 활성화합니다. 기본값은 꺼짐이며 반복·모델·도구 호출·시간 한도를 설정할 수 있습니다. 실제 진단 요청은 별도 허용이 필요합니다.
- 기존 네 환경변수와 일반 PostgreSQL, 서비스 이미지 하나의 배포 방식을 유지합니다. 원본 Docker 실행기·클라우드 검색·원격 텔레메트리는 초기화하지 않습니다.

조회에는 에이전트·서비스·발견 건·진단 조회 권한이 모두 필요하고, 생성에는 에이전트 실행·AI 사용 권한을 추가로 요구합니다. 기존 역할 설정에서 새 권한을 확인하세요. 에이전트 완료가 발견 건의 자동 해결을 뜻하지는 않습니다.

[PentAGI 원본 출처와 통합 범위](https://github.com/hkjang/hunter/blob/main/docs/architecture/pentagi-integration.md)를 공개하며, 라이선스 고지는 이미지의 `/usr/share/licenses/hunter/`에 포함합니다.

"""
notes = f"""## Hunter {tag}

폐쇄망 반입용 서비스 Docker 이미지입니다. PostgreSQL은 사내에 별도 준비합니다.

- 이미지: {tick}hunter:{tag}{tick}
- 유일한 첨부 자산: {tick}hunter-{tag}.tar.gz{tick}
- 플랫폼: {tick}linux/amd64{tick}
- SHA-256: {tick}{checksum}{tick}

{features}### 설치

{fence}sh
docker load -i hunter-{tag}.tar.gz
docker compose up -d
{fence}

[설치 및 관리자 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 가이드](https://hkjang.github.io/hunter/guides/user-guide.html)

GitHub가 자동 표시하는 소스 코드 다운로드는 릴리즈 첨부 자산과 별개입니다.
"""
Path(output).write_text(notes, encoding="utf-8")
