import { readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, resolve, extname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const docs=resolve(root,'docs');
const files=[];
async function walk(path){
  for(const entry of await readdir(path,{withFileTypes:true})){
    if(['node_modules','.git'].includes(entry.name))continue;
    const full=resolve(path,entry.name);
    if(entry.isDirectory())await walk(full);
    else if(['.html','.css'].includes(extname(entry.name)))files.push(full);
  }
}
await walk(docs);
const failures=[];
for(const file of files){
  const raw=await readFile(file,'utf8');
  const links=extname(file)==='.html'?[...raw.matchAll(/(?:href|src)="([^"]+)"/g)].map(m=>m[1]):[...raw.matchAll(/url\(['"]?([^)'"]+)['"]?\)/g)].map(m=>m[1]);
  for(const value of links){
    if(/^(?:https?:|data:|mailto:|#)/i.test(value))continue;
    const path=decodeURIComponent(value.split('#')[0].split('?')[0]);
    if(!path)continue;
    const target=resolve(dirname(file),path);
    if(!existsSync(target))failures.push(relative(root,file)+': '+value);
  }
  if(extname(file)==='.html'){
    for(const json of raw.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)){
      try{JSON.parse(json[1]);}catch(e){failures.push(relative(root,file)+': JSON-LD '+e.message);}
    }
    if(!raw.includes('lang="ko"'))failures.push(relative(root,file)+': 한국어 lang 속성 누락');
    if(!raw.includes('name="viewport"'))failures.push(relative(root,file)+': viewport 누락');
  }
}
for(const name of ['user-guide','admin-guide']){
  const pdf=resolve(docs,'guides',name+'.pdf');
  if(!existsSync(pdf)) failures.push('PDF 누락: '+name);
  else {const data=await readFile(pdf);if(data.subarray(0,5).toString()!=='%PDF-')failures.push('올바른 PDF가 아님: '+name);}
}
const manifest=JSON.parse(await readFile(resolve(docs,'screenshot-manifest.json'),'utf8'));
for(const screen of manifest){
  const path=resolve(docs,screen.path);
  if(!existsSync(path))failures.push('화면 캡처 누락: '+screen.path);
  else {const info=await stat(path);if(info.size<5000)failures.push('화면 캡처가 비정상적으로 작음: '+screen.path);}
}
if(failures.length){console.error(failures.join('\n'));process.exit(1);}
console.log('문서 링크, JSON-LD, 한국어·모바일 메타데이터, PDF 2개, 실제 화면 '+manifest.length+'개 확인 완료.');
