#!/usr/bin/env node
// The release workflow builds its public body with scripts/release-notes.py on a
// pushed tag, where a mistake is already published. CI only compiled the script
// until now, so a VERSION bump without its own notes section stayed invisible
// until the release ran. This actually generates the body for the current
// VERSION and checks it describes this release, then checks the next minor does
// not silently inherit this one's section.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const generator = path.join(root, "scripts", "release-notes.py");
const version = readFileSync(path.join(root, "VERSION"), "utf8").trim();
const work = mkdtempSync(path.join(tmpdir(), "hunter-release-notes-"));
const failures = [];

function check(condition, message) {
  if (!condition) failures.push(message);
}

// Distinct bytes per tag so a stale output file cannot pass the checksum test.
function generate(tag) {
  const archive = path.join(work, `hunter-${tag}.tar.gz`);
  const body = Buffer.from(`hunter release archive ${tag}`, "utf8");
  writeFileSync(archive, body);
  const output = path.join(work, `${tag}.md`);
  execFileSync("python3", [generator, tag, archive, output], {
    cwd: root,
    stdio: ["ignore", "ignore", "pipe"],
  });
  return {
    notes: readFileSync(output, "utf8"),
    checksum: createHash("sha256").update(body).digest("hex"),
  };
}

function refuses(args, message) {
  try {
    execFileSync("python3", [generator, ...args], {
      cwd: root,
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch {
    return;
  }
  failures.push(message);
}

const tag = `v${version}`;
const { notes, checksum } = generate(tag);
const [major, minor] = version.split(".").map((part) => Number(part));
const series = `v${major}.${minor}.0`;

check(notes.includes(`## Hunter ${tag}`), `${tag} notes have no release title`);
check(
  notes.includes(`\`hunter:${tag}\``),
  `${tag} notes do not name the image tag`,
);
check(
  notes.includes(`\`hunter-${tag}.tar.gz\``),
  `${tag} notes do not name the only release asset`,
);
check(
  notes.includes(`\`${checksum}\``),
  `${tag} notes carry a SHA-256 that is not the archive digest`,
);
check(
  notes.includes(`docker load -i hunter-${tag}.tar.gz`),
  `${tag} notes do not show loading this release's archive`,
);

// Every section this generator holds from v1.10.0 on links to its own release
// note in docs/, so the link is what identifies the section that was selected.
const linked = [...notes.matchAll(/docs\/release-v([0-9]+\.[0-9]+\.[0-9]+)\.md/g)]
  .map((match) => match[1])
  .filter((found, index, all) => all.indexOf(found) === index);
if (major > 1 || minor >= 10) {
  check(
    linked.includes(`${major}.${minor}.0`),
    `${tag} notes have no release section of their own — add a v${major}.${minor} branch to scripts/release-notes.py`,
  );
  check(
    linked.length <= 1,
    `${tag} notes link several release notes: ${linked.join(", ")}`,
  );
  check(
    existsSync(path.join(root, "docs", `release-${series}.md`)),
    `docs/release-${series}.md is linked from the notes but missing`,
  );
}

// The branch chain used to be open ended, so a release above the newest branch
// republished that branch's features and its link under the new tag.
const next = `v${major}.${minor + 1}.0`;
const inherited = [
  ...generate(next).notes.matchAll(/docs\/release-v([0-9]+\.[0-9]+\.[0-9]+)\.md/g),
].map((match) => match[1]);
check(
  !inherited.includes(`${major}.${minor}.0`),
  `${next} notes reuse the ${series} release section, so an unreleased version would advertise ${series} features`,
);

refuses([version, path.join(work, `hunter-${tag}.tar.gz`), path.join(work, "bad-tag.md")], "a tag without the v prefix was accepted");
refuses([tag, path.join(work, `hunter-${next}.tar.gz`), path.join(work, "bad-asset.md")], "an archive name from another tag was accepted");

if (failures.length > 0) {
  for (const failure of failures) console.error(`릴리즈 본문 검사 실패: ${failure}`);
  process.exit(1);
}
console.log(
  `릴리즈 본문 ${tag} 확인 완료: 제목·이미지·자산·SHA-256·설치 절차와 ${series} 전용 안내, 다음 버전 상속 금지.`,
);
