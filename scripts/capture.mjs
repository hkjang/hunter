import { chromium } from '../docs/node_modules/playwright/index.mjs';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
const base = process.argv[2] || 'http://localhost:8080';
const login = JSON.parse(await readFile('.tmp/dev-login.json','utf8'));
const agentDemo = JSON.parse(await readFile('.tmp/demo-agent.json','utf8'));
const version = (await readFile('VERSION','utf8')).trim();
await mkdir('docs/images',{recursive:true});await mkdir('.tmp',{recursive:true});
const browser = await chromium.launch({headless:true});
const context = await browser.newContext({viewport:{width:1512,height:1050},deviceScaleFactor:1,locale:'ko-KR',timezoneId:'Asia/Seoul'});
const page = await context.newPage();
const errors=[];const responses=[];
page.on('pageerror',e=>errors.push(e.message));
page.on('console',m=>{if(m.type()==='error'&&!m.text().includes('401 (Unauthorized)'))errors.push(m.text());});
page.on('response',r=>{if(r.status()>=400&&!r.url().includes('/api/auth/me')&&!r.url().includes('/api/settings/public'))responses.push({status:r.status(),url:r.url()});});
async function settle(){await page.waitForLoadState('networkidle');await page.evaluate(()=>document.fonts.ready);await page.waitForTimeout(200);}
async function shot(name){await settle();await page.screenshot({path:`docs/images/${name}.png`,fullPage:true});}
await page.goto(base+'/login');await shot('login');await page.setViewportSize({width:390,height:844});await shot('mobile-login');await page.setViewportSize({width:1512,height:1050});
await page.getByLabel('사용자 아이디').fill(login.username);await page.getByLabel('비밀번호').fill(login.password);await page.getByRole('button',{name:'로그인',exact:true}).click();await page.waitForURL('**/dashboard');await settle();
const routes=[['dashboard','/dashboard'],['services','/services'],['findings','/findings'],['scans','/scans'],['schedules','/schedules'],['graph','/graph'],['scenarios','/scenarios'],['remediations','/remediations'],['reports','/reports'],['contributions','/contributions'],['copilot','/copilot'],['agents','/agents'],['agent-detail','/agents/'+agentDemo.run_id],['admin-integrations','/admin/integrations'],['admin-discovery','/admin/discovery'],['admin-policies','/admin/policies'],['admin-scopes','/admin/scopes'],['admin-auth-profiles','/admin/auth-profiles'],['admin-workers','/admin/workers'],['admin-users','/admin/users'],['admin-audit','/admin/audit'],['admin-settings','/admin/settings'],['personal-profile','/personal/profile'],['personal-keys','/personal/keys']];
const checks=[];
for(const [name,path] of routes){await page.goto(base+path);await settle();const title=await page.locator('h1').first().textContent();if(!title||title.includes('찾을 수 없습니다'))throw new Error('Missing route '+path);await page.reload();await settle();if(new URL(page.url()).pathname!==path)throw new Error('Refresh lost path '+path);await shot(name);checks.push({path,title,refresh:true});console.log('Captured '+path);}
await page.goto(base+'/admin/settings');await settle();
for(const [tab,name] of [['SSO · 로그인','oidc'],['AI 분석','ai'],['에이전트 진단','agents'],['검토 · 승인','workflow'],['보안 · 세션','security'],['역할 · 권한','roles']]){await page.getByRole('button',{name:tab,exact:true}).click();await shot('admin-settings-'+name);}
// Optional workflow is enabled only for the screenshot, then restored.
let pendingID;
const originalSettingsResponse=await context.request.get(base+'/api/settings');
if(!originalSettingsResponse.ok())throw new Error('Cannot read workflow settings before capture');
const originalWorkflow=(await originalSettingsResponse.json()).workflow;
if(!originalWorkflow)throw new Error('Missing workflow settings before capture');
try {
 const setting=await context.request.put(base+'/api/settings/workflow',{headers:{'X-Hunter-CSRF':'1'},data:{approval_enabled:true}});if(!setting.ok())throw new Error('Workflow enable failed');
 const fixtures=JSON.parse(await readFile('.tmp/demo-fixtures.json','utf8'));
 const pending=await context.request.post(base+'/api/scans',{headers:{'X-Hunter-CSRF':'1'},data:{service_id:fixtures.services[0].id,profile:'http-baseline'}});if(!pending.ok())throw new Error('Pending demo scan failed '+await pending.text());pendingID=(await pending.json()).id;
 await page.goto(base+'/approvals');await shot('approvals');await page.setViewportSize({width:390,height:844});await shot('mobile-approvals');await page.setViewportSize({width:1512,height:1050});
} finally {
 if(pendingID)await context.request.post(base+`/api/scans/${pendingID}/cancel`,{headers:{'X-Hunter-CSRF':'1'}});
 const restored=await context.request.put(base+'/api/settings/workflow',{headers:{'X-Hunter-CSRF':'1'},data:originalWorkflow});
 if(!restored.ok())throw new Error('Workflow restore failed');
}
await page.goto(base+'/dashboard');await settle();await page.locator('.profile-trigger').click();await page.getByText('hunter · 서비스 버전 v'+version,{exact:true}).waitFor();await shot('profile-menu');await page.keyboard.press('Escape');
const mobile=[];
await page.setViewportSize({width:390,height:844});
for(const [name,path] of routes){await page.goto(base+path);await settle();const sizes=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(sizes.scroll>sizes.width+1)errors.push(`Mobile horizontal overflow ${path}: ${sizes.scroll}/${sizes.width}`);await shot('mobile-'+name);mobile.push({path,...sizes});}
await page.goto(base+'/admin/settings');await settle();await page.getByRole('button',{name:'에이전트 진단',exact:true}).click();await shot('mobile-admin-settings-agents');
await page.getByRole('button',{name:'메뉴 열기',exact:true}).click();await shot('mobile-menu');
await writeFile('.tmp/browser-checks.json',JSON.stringify({checkedAt:new Date().toISOString(),checks,mobile,errors,responses},null,2));
await browser.close();
if(errors.length||responses.length)throw new Error(JSON.stringify({errors,responses},null,2));
console.log(`Verified ${checks.length} desktop routes + refresh, ${mobile.length} mobile routes, all settings tabs, optional approval, profile version. No unexpected browser or HTTP errors.`);
