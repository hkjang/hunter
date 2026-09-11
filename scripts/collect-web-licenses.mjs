#!/usr/bin/env node
/** Collect installed npm production dependency notices without network access.
 * Usage: node scripts/collect-web-licenses.mjs <empty-output-directory>
 * Run `npm ci` in web/ first. This command never installs or fetches packages.
 * Audited local overrides live under license-notices/web-overrides/name@version.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptFile = fileURLToPath(import.meta.url);
const repositoryRoot = path.resolve(path.dirname(scriptFile), '..');
const noticeName = /^(?:licen[cs]es?|notices?|copying|copyright|ofl)(?:$|[._-])/i;
const licenseName = /^(?:licen[cs]es?|copying|ofl)(?:$|[._-])/i;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const slash = value => value.split(path.sep).join('/');
function inside(base, candidate) {
  const relative = path.relative(base, candidate);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}
function safeRelative(value) {
  return typeof value === 'string' && value.length > 0 && !path.isAbsolute(value) && !value.includes('\\') && value.split('/').every(part => part && part !== '.' && part !== '..');
}
async function nonemptyFile(file) {
  const info = await stat(file);
  if (!info.isFile() || info.size < 1 || info.size > 4 * 1024 * 1024) throw new Error(`Missing, empty, or oversized notice: ${file}`);
  return readFile(file);
}
async function noticeFiles(packageDir) {
  const result = [];
  async function visit(directory, relative, legalDirectory, depth) {
    if (depth > 6) throw new Error(`Notice directory nesting exceeds limit: ${directory}`);
    for (const entry of (await readdir(directory, {withFileTypes:true})).sort((a,b) => a.name.localeCompare(b.name,'en'))) {
      if (!legalDirectory && !noticeName.test(entry.name)) continue;
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Notice symlinks require an audited local override: ${file}`);
      if (entry.isDirectory()) await visit(file, name, true, depth + 1);
      else if (entry.isFile()) result.push({relative:name, bytes:await nonemptyFile(file), source:`package:${name}`, kind:'notice'});
    }
  }
  await visit(packageDir, '', false, 0);
  return result;
}
async function overrideFiles(overrideDir, pkg, installedNotices) {
  const directory = path.resolve(overrideDir, `${pkg.name}@${pkg.version}`);
  if (!inside(path.resolve(overrideDir), directory)) throw new Error(`Unsafe package name in override: ${pkg.name}`);
  let provenanceBytes;
  try { provenanceBytes = await readFile(path.join(directory, 'PROVENANCE.json')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const provenance = JSON.parse(provenanceBytes);
  if (provenance.name !== pkg.name || provenance.version !== pkg.version) throw new Error(`Override package/version mismatch: ${pkg.name}@${pkg.version}`);
  if (typeof provenance.source_url !== 'string' || !/^https:\/\//.test(provenance.source_url) || typeof provenance.source_ref !== 'string' || !provenance.source_ref.trim()) throw new Error(`Override requires pinned source URL and reference: ${pkg.name}@${pkg.version}`);
  if (!Array.isArray(provenance.files) || !provenance.files.length) throw new Error(`Override has no pinned notice files: ${pkg.name}@${pkg.version}`);
  const result = [...installedNotices];
  const seen = new Set(installedNotices.map(file => file.relative));
  for (const notice of provenance.files) {
    if (!safeRelative(notice.path) || !/^[a-f0-9]{64}$/i.test(notice.sha256 || '')) throw new Error(`Invalid override file/hash: ${pkg.name}@${pkg.version}`);
    if (seen.has(notice.path)) throw new Error(`Duplicate package/override notice path: ${pkg.name}@${pkg.version}/${notice.path}`);
    const fullPath = path.resolve(directory, notice.path);
    if (!inside(directory, await realpath(fullPath))) throw new Error(`Override file escapes its directory: ${fullPath}`);
    const bytes = await nonemptyFile(fullPath);
    if (sha256(bytes) !== notice.sha256.toLowerCase()) throw new Error(`Override notice SHA256 mismatch: ${pkg.name}@${pkg.version}/${notice.path}`);
    seen.add(notice.path);
    result.push({relative:notice.path, bytes, source:`override:${slash(path.relative(repositoryRoot, fullPath))}`, kind:'notice'});
  }
  result.push({relative:'PROVENANCE.json',bytes:provenanceBytes,source:`override:${slash(path.relative(repositoryRoot,path.join(directory,'PROVENANCE.json')))}`,kind:'provenance'});
  return result;
}

export async function collectWebLicenses({outputDir, webDir=path.join(repositoryRoot,'web'), overrideDir=path.join(repositoryRoot,'scripts/license-notices/web-overrides')}={}) {
  if (!outputDir) throw new Error('Usage: node scripts/collect-web-licenses.mjs <empty-output-directory>');
  outputDir = path.resolve(outputDir);
  webDir = await realpath(webDir);
  // An existing nonempty output is never removed or mixed with this build.
  try { if ((await readdir(outputDir)).length) throw new Error(`License output directory must be empty: ${outputDir}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const lockBytes = await readFile(path.join(webDir,'package-lock.json'));
  const lock = JSON.parse(lockBytes);
  if (!lock.packages) throw new Error('package-lock.json must contain installed package locations (lockfile v2 or newer)');
  const command = ['ls','--omit=dev','--parseable','--all'];
  let listing;
  try {
    listing = execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', command, {
      cwd:webDir, encoding:'utf8', maxBuffer:16*1024*1024,
      env:{...process.env,npm_config_offline:'true',npm_config_audit:'false',npm_config_fund:'false',npm_config_update_notifier:'false'},
      stdio:['ignore','pipe','pipe'],
    });
  } catch (error) { throw new Error(`Cannot enumerate installed npm production dependencies: ${String(error.stderr || error.message).trim()}`); }
  const directories = [...new Set((await Promise.all(listing.trim().split(/\r?\n/).filter(Boolean).map(file => realpath(file)))).filter(file => file !== webDir))];
  if (!directories.length) throw new Error('Installed npm production dependency tree is empty');
  const components = [], missing = [], planned = [];
  for (const directory of directories) {
    if (!inside(path.join(webDir,'node_modules'),directory)) throw new Error(`Production dependency is outside installed node_modules: ${directory}`);
    const packageBytes = await readFile(path.join(directory,'package.json'));
    const pkg = JSON.parse(packageBytes);
    if (!pkg.name || !pkg.version) throw new Error(`Package name/version missing: ${directory}`);
    const installedPath = slash(path.relative(webDir,directory));
    const locked = lock.packages[installedPath];
    if (!locked || locked.version !== pkg.version) throw new Error(`Installed package differs from package-lock.json: ${pkg.name}@${pkg.version}`);
    let notices = await noticeFiles(directory);
    const hasLicense = files => files.some(file => file.kind === 'notice' && file.relative.split('/').some(part => licenseName.test(part)));
    if (!hasLicense(notices)) notices = await overrideFiles(overrideDir,pkg,notices) || notices;
    if (!hasLicense(notices)) { missing.push(`${pkg.name}@${pkg.version}`); continue; }
    const componentPath = `components/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`;
    const files = notices.map(notice => {
      const relative = `${componentPath}/${notice.relative}`;
      planned.push({path:relative,bytes:notice.bytes});
      return {path:relative,source:notice.source,kind:notice.kind,sha256:sha256(notice.bytes),bytes:notice.bytes.length};
    }).sort((a,b) => a.path.localeCompare(b.path,'en'));
    components.push({name:pkg.name,version:pkg.version,license:pkg.license || null,installed_path:installedPath,package_json_sha256:sha256(packageBytes),lock_integrity:locked.integrity || null,files});
  }
  if (missing.length) throw new Error(`Required license originals missing for ${missing.length} production dependencies:\n${missing.sort().map(name=>'  '+name).join('\n')}\nAdd a pinned, hash-verified local override; this collector never downloads license text.`);
  components.sort((a,b) => a.name.localeCompare(b.name,'en') || a.version.localeCompare(b.version,'en') || a.installed_path.localeCompare(b.installed_path,'en'));
  const destinations = new Map();
  for (const file of planned) {
    if (destinations.has(file.path) && !destinations.get(file.path).equals(file.bytes)) throw new Error(`Conflicting notices for identical package/version: ${file.path}`);
    destinations.set(file.path,file.bytes);
  }
  const manifest = {
    schema_version:1,generated_at:new Date().toISOString(),collection:'installed npm production dependency graph',
    note:'Includes installed production peer dependencies and their type declarations; excludes dev-only build tools. No network requests are made by this collector.',
    npm_command:['npm',...command],lockfile_sha256:sha256(lockBytes),component_count:components.length,
    notice_file_count:new Set(components.flatMap(component=>component.files.filter(file=>file.kind==='notice').map(file=>file.path))).size,
    copied_file_count:destinations.size,components,
  };
  // Validate every package and override before writing any output files.
  await mkdir(outputDir,{recursive:true});
  for (const [relative,bytes] of [...destinations].sort(([a],[b])=>a.localeCompare(b,'en'))) {
    const target = path.join(outputDir,relative);
    await mkdir(path.dirname(target),{recursive:true});
    await writeFile(target,bytes,{flag:'wx'});
  }
  await writeFile(path.join(outputDir,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
  return manifest;
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptFile) {
  try {
    if (process.argv.length !== 3) throw new Error('Usage: node scripts/collect-web-licenses.mjs <empty-output-directory>');
    const manifest = await collectWebLicenses({outputDir:process.argv[2]});
    console.log(JSON.stringify({components:manifest.component_count,notice_files:manifest.notice_file_count,copied_files:manifest.copied_file_count,output_files:manifest.copied_file_count+1,output:path.resolve(process.argv[2])}));
  } catch (error) { console.error(error.message);process.exitCode=1; }
}
