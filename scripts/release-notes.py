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
notes = f"""## Hunter {tag}

폐쇄망 반입용 서비스 Docker 이미지입니다. PostgreSQL은 사내에 별도 준비합니다.

- 이미지: {tick}hunter:{tag}{tick}
- 유일한 첨부 자산: {tick}hunter-{tag}.tar.gz{tick}
- 플랫폼: {tick}linux/amd64{tick}
- SHA-256: {tick}{checksum}{tick}

{fence}sh
docker load -i hunter-{tag}.tar.gz
docker compose up -d
{fence}

[설치 및 관리자 가이드](https://hkjang.github.io/hunter/guides/admin-guide.html) · [사용자 가이드](https://hkjang.github.io/hunter/guides/user-guide.html)

GitHub가 자동 표시하는 소스 코드 다운로드는 릴리즈 첨부 자산과 별개입니다.
"""
Path(output).write_text(notes, encoding="utf-8")
