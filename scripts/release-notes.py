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
if version >= (1, 1, 0):
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
