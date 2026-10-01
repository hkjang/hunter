# Hunter v1.19.0

프런트엔드 **회귀 검사**가 npm 을 실행한 그 Node 해석기에서 돌도록 고정한 릴리즈입니다. 사용자가 보는 화면과 동작, 저장되는 값, 서버 API·권한·감사 기록은 달라지지 않으며 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

사용자 화면의 동작은 달라지지 않습니다. 이번 릴리즈는 검사가 조용히 0건 실행되는 일을 막는 검증 경로 수정입니다.

- **검사가 0건 실행되고도 성공처럼 보이던 경로.** `web/package.json` 의 `test` 스크립트는 맨 `node` 를 불렀습니다. npm 은 스크립트에 주는 PATH 앞에 상위 모든 `node_modules/.bin` 을 붙이므로, 상위 디렉터리에 `node` 패키지가 설치돼 있으면 `npm test` 에서만 그 구버전 해석기가 실제 해석기를 가립니다. 가려진 Node 20에서는 `node: bad option: --experimental-strip-types` 로 종료 코드 9를 내며 시험 19개 파일이 0건 실행됐고, 이 상태가 검증과 릴리즈 워크플로를 막았습니다.
- **npm 자신의 해석기를 그대로 씁니다.** 이제 스크립트는 `${npm_node_execpath:-node}` 로 npm 을 실행한 Node 를 호출합니다. PATH 가 어떻게 바뀌어도 `npm --prefix web test` 는 `npm --prefix web ci` 를 돌린 그 해석기에서 실행됩니다.
- **플래그를 떼는 것만으로는 부족했습니다.** `--experimental-strip-types` 는 Node 22.18부터 불필요하므로 함께 뗐습니다. 다만 플래그만 떼고 PATH 가 고른 Node 20에서 돌리면 그 줄에는 `.ts` 타입 스트리핑이 없어 19개 파일이 0건 통과·19건 실패로 끝납니다. 해석기 고정과 플래그 제거가 함께 필요합니다.

## 운영 조건과 한계

검사 파일 목록과 단정은 그대로이며 서비스 코드·화면·API 필드·권한·관리자 설정은 바꾸지 않았습니다. `AGENTS.md` 에 이 호출을 맨 `node` 로 되돌리지 않는 이유를 적었습니다. 이 수정은 `npm test` 가 쓰는 해석기만 고정하며 `npm run build`·`npm run typecheck` 처럼 `node_modules/.bin` 의 도구를 직접 부르는 스크립트의 해석기 선택은 npm 의 기존 동작을 그대로 따릅니다. `npm_node_execpath` 가 없는 실행기에서는 기존처럼 PATH 의 `node` 로 돌아갑니다.

## 검증과 배포

`npm --prefix web ci` 후 `npm --prefix web test` 로 19개 파일 104개 검사가 실행되고 실패·건너뜀이 0개인 것을 확인했습니다. `npm --prefix web run build`(tsc 포함)를 통과한 결과를 `internal/webassets/dist` 에 반영한 뒤 `go vet ./...` 와 `go build ./cmd/hunter` 를 통과했습니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.19.0` · 유일한 첨부 자산: `hunter-v1.19.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.18.0 릴리즈 노트](release-v1.18.0.md)
