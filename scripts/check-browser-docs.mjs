import { chromium } from '../docs/node_modules/playwright/index.mjs';
import { writeFile } from 'node:fs/promises';
const base=process.argv[2]||'http://127.0.0.1:8090';
const browser=await chromium.launch();const page=await browser.newPage({viewport:{width:1440,height:1000}});
const errors=[],checks=[];
page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400)errors.push(r.url()+' '+r.status());});
for(const mobile of [false,true]){
 await page.setViewportSize(mobile?{width:390,height:844}:{width:1440,height:1000});
 for(const path of ['/','/screenshots.html','/guides/user-guide.html','/guides/admin-guide.html']){
  await page.goto(base+path);await page.locator('img').evaluateAll(images=>images.forEach(i=>i.loading='eager'));await page.waitForLoadState('networkidle');
  await page.locator('img').evaluateAll(images=>Promise.all(images.map(i=>i.decode().catch(()=>{}))));
  const missing=await page.locator('img').evaluateAll(images=>images.filter(i=>i.getAttribute('src')&&(!i.complete||i.naturalWidth===0)).map(i=>i.src));errors.push(...missing);
  if(mobile&&await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))errors.push('Mobile overflow '+path);
  checks.push({path,mobile,title:await page.title()});
 }
}
await writeFile('.tmp/docs-browser-checks.json',JSON.stringify({checks,errors},null,2));await browser.close();
if(errors.length)throw new Error(errors.join('\n'));console.log('Four documentation pages passed desktop/mobile rendering, all images loaded, no errors or overflow.');
