import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(root, 'web/node_modules/@fontsource/noto-sans-kr');
const target = resolve(root, 'docs/assets/fonts');
await mkdir(target, {recursive:true});
if (!existsSync(source)) {
  if (existsSync(resolve(root,'docs/assets/fonts.css'))) process.exit(0);
  throw new Error('먼저 npm --prefix web ci로 UI 폰트를 설치하세요.');
}
let output='';
for(const weight of [400,700]) {
  const css=await readFile(resolve(source,weight+'.css'),'utf8');
  for(const match of css.matchAll(/url\(\.\/files\/([^)]*\.woff2)\)/g)) {
    await copyFile(resolve(source,'files',match[1]),resolve(target,match[1]));
  }
  output+=css.replaceAll('./files/','./fonts/').replace(/, url\([^)]*\.woff\) format\('woff'\)/g,'')+'\n';
}
await writeFile(resolve(root,'docs/assets/fonts.css'),output);
await copyFile(resolve(source,'LICENSE'),resolve(target,'LICENSE'));
await copyFile(resolve(root,'web/public/favicon.svg'),resolve(root,'docs/assets/favicon.svg'));
console.log('문서 로고와 한국어 폰트를 로컬 자산으로 준비했습니다.');
