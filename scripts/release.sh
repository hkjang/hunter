#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
release_version="${1:-$(cat VERSION)}"
release_version="${release_version#v}"
if [[ ! "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid release version: %s\n' "$release_version" >&2
  exit 1
fi
if [[ "$release_version" != "$(tr -d '\r\n' < VERSION)" ]]; then
  printf 'Release version must match VERSION.\n' >&2
  exit 1
fi
release_image="hunter:v${release_version}"
release_archive="hunter-v${release_version}.tar.gz"
mkdir -p dist
docker build --platform linux/amd64 --build-arg "VERSION=$release_version" --tag "$release_image" .
docker image save "$release_image" | gzip -n -9 > "dist/${release_archive}.tmp"
gzip --test "dist/${release_archive}.tmp"
mv "dist/${release_archive}.tmp" "dist/${release_archive}"
printf '\nImage: %s\nRelease asset: dist/%s\n' "$release_image" "$release_archive"
sha256sum "dist/${release_archive}"
