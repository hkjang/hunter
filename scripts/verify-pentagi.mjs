import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'third_party', 'pentagi');
const manifest = JSON.parse(await readFile(resolve(root, 'UPSTREAM.json'), 'utf8'));
if (manifest.repository !== 'https://github.com/vxcontrol/pentagi' ||
    manifest.commit !== 'ea665308baaff015b226f308438a68d929d0f29b' || manifest.license !== 'MIT') {
  throw new Error('Unexpected PentAGI source identity; review the pinned source before updating it.');
}
const files = Object.entries(manifest.original_files_sha256 || {});
if (!files.length) throw new Error('PentAGI original source hash manifest is empty.');
for (const [name, expected] of files) {
  const path = resolve(root, name);
  if (!path.startsWith(root + sep) || !/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error('Invalid PentAGI manifest entry: ' + name);
  }
  const actual = createHash('sha256').update(await readFile(path)).digest('hex');
  if (actual !== expected) throw new Error('PentAGI original source changed: ' + name);
}
console.log(`Verified ${files.length} pinned PentAGI original files at ${manifest.commit}.`);
