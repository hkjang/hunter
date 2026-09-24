# Hunter v1.14.0

**보고서 내보내기 CSV**의 수식 방지 판정을 화면의 목록 CSV 내려받기와 같게 맞춘 릴리즈입니다. 앞에 공백이 붙은 `=1+1` 같은 값이 서버 내보내기에서만 그대로 나가던 차이를 없앴습니다. 기능·설정·권한은 달라지지 않으며 일반 PostgreSQL·네 환경변수·서비스 Docker 이미지 하나의 기본 배포를 유지합니다.

## 사용자가 달라지는 점

- `GET /api/reports/export?format=csv` 는 지금까지 값의 **첫 글자만** 검사했기 때문에 ` =1+1` 처럼 공백이나 제어문자가 앞에 붙은 제목·서비스 ID·출처·CVE 를 `'` 없이 내보냈습니다. 이제 앞쪽 공백류를 건너뛴 뒤 `=`·`+`·`-`·`@` 를 찾으면 `'` 를 붙입니다. 값이 탭·CR·LF 로 시작할 때 `'` 를 붙이던 기존 동작은 그대로입니다.
- 화면의 목록 CSV 내려받기(`web/src/list-export.ts`)는 이미 같은 방식이었으므로, 같은 발견 건을 목록에서 받든 보고서 내보내기에서 받든 결과가 같아집니다.
- 붙는 `'` 는 **CSV 내보내기에만** 적용합니다. DB 에 저장한 원래 값, `format=json` 내보내기, 목록·상세 화면 표시는 달라지지 않습니다. 접근 범위 검사와 감사 기록(`reports.export`)도 기존과 같습니다.

## 운영 조건과 한계

이것은 스프레드시트 애플리케이션이 따옴표로 감싼 필드의 수식도 실행할 수 있다는 점에 대한 **내보내기 측 방어**이며, 입력 값 자체를 검사하거나 거부하지 않습니다. 어떤 문자를 공백으로 볼지는 두 구현이 `internal/app/testdata/csv-safety.json` 의 공유 벡터를 함께 읽어 고정합니다. ECMAScript `\s` 와 C0 제어문자를 공백으로 보므로 `FEFF` 는 건너뛰고 `0085`·`180E`·`200B` 는 건너뛰지 않습니다. 관리자 설정 항목·API 계약·권한은 추가하거나 바꾸지 않았습니다.

## 검증과 배포

공유 벡터 83개를 Go 의 `TestCSVSafeSharedVectors`·`TestReportCSVFormulaSafety` 와 프런트엔드의 `convenience.test.mjs` 가 같은 파일에서 읽어 검사합니다. Go 쪽은 실제 발견 건을 등록해 `/api/reports/export?format=csv` 응답을 CSV 로 다시 파싱하고, 다른 팀 서비스의 발견 건이 섞이지 않는지와 `format=json` 이 원래 값을 그대로 돌려주는지도 함께 확인합니다. 릴리즈 커밋에서 실행한 검사와 건너뛴 검사는 [검증 기록](validation.md)에 적었습니다.

화면 캡처는 v1.9.0의 검증 장면을 보존했습니다. 가이드·README·llms.txt·openapi.json 의 버전 표기를 갱신하고 가이드 HTML·PDF 를 재생성했습니다.

배포 이미지: `hunter:v1.14.0` · 유일한 첨부 자산: `hunter-v1.14.0.tar.gz`.

[사용자 가이드](guides/user-guide.html) · [관리자 가이드](guides/admin-guide.html) · [검증 기록](validation.md) · [v1.13.0 릴리즈 노트](release-v1.13.0.md)
