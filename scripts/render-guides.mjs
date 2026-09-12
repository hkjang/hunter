import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const require=createRequire(resolve(root,'docs/package.json'));
const MarkdownIt=require('markdown-it');
const markdown=new MarkdownIt({html:false,linkify:true,typographer:true});
const htmlOnly=process.argv.includes('--html-only');
const escape=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
const entries=[['user-guide','사용자 가이드','일상 업무, 발견 건, 진단, 개인화와 API 키 사용 절차'],['admin-guide','관리자 가이드','폐쇄망 설치, Keycloak, AI, 권한, 연동, 정책과 백업 운영 절차']];
const routes=[
['login','로그인','로컬 계정과 SSO 로그인, 서비스 버전'],
['dashboard','보안 현황','서비스와 발견 건의 위험도, 최근 진단'],
['quick-navigation','빠른 이동','현재 권한 안의 메뉴 검색, 즐겨찾기와 최근 방문'],
['quick-navigation-search','빠른 이동 검색','한글 메뉴명·영어 별칭·초성으로 메뉴 찾기'],
['services','서비스 자산','서비스·환경·망·담당자와 공격 표면'],
['findings','발견 건','증거, 위험도, 개선과 재검증 상태'],
['scans','진단 작업','승인된 진단 요청과 실제 실행 이력'],
['schedules','진단 예약','현재 권한과 범위를 확인하는 주기적 진단'],
['graph','관계 그래프','등록 서비스·구성요소·발견 건의 관계'],
['scenarios','권한 검증','역할별 합성 데이터 접근 비교'],
['remediations','개선 요청','개선 초안과 외부 시스템 발송'],
['reports','보고서','위험 현황과 JSON·CSV 내보내기'],
['contributions','기여 현황','검토된 보안 기여 점수'],
['copilot','AI 분석 도우미','사내 모델과 기본 스트리밍 대화'],
['agents','에이전트 진단','서비스별 목표와 실행 상태, 새 에이전트 실행'],
['agent-detail','에이전트 실행 상세','목표·응답·도구·실행 기록·연결 진단과 중지'],
['approvals','검토·승인','관리자가 활성화한 경우의 팀장 검토'],
['admin-integrations','연동 관리','REST·PostgreSQL·웹훅·외부 결과'],
['admin-discovery','자동발견 후보','사내 카탈로그에서 수집한 등록 후보'],
['admin-policies','실행 정책','진단 실행 한도와 보호 정책'],
['admin-scopes','진단 허용 범위','허용 대상·경로·대역과 만료'],
['admin-auth-profiles','인증 프로파일','대상 서비스의 테스트 인증'],
['admin-workers','워커·이벤트','내장 워커 상태와 변경 이벤트'],
['admin-users','사용자 관리','사용자·역할·팀·비활성화'],
['admin-audit','감사 기록','수행자·대상·행위·시각'],
['admin-settings','서비스 설정','서비스 전체의 운영 설정'],
['personal-profile','내 프로필','표시 이름·시작 화면·비밀번호'],
['personal-keys','개인 API 키','발급·권한 수정·회전·폐기']
];
const agentTabs=[
['agent-detail-overview','목표와 결과','에이전트 실행 목표와 최종 결과'],
['agent-detail-messages','에이전트 응답','실시간 응답과 모델의 설명'],
['agent-detail-tools','도구 호출','실제로 호출한 Hunter 도구와 결과'],
['agent-detail-logs','실행 기록','시간순 이벤트와 실행 상태 전환'],
['agent-detail-scans','연결된 진단','에이전트가 요청한 진단의 실제 상태']
];
const version=(await readFile(resolve(root,'VERSION'),'utf8')).trim();
await mkdir(resolve(root,'docs/guides'),{recursive:true});
for(const [name,title,description] of entries) {
  const raw=await readFile(resolve(root,'docs/guides',name+'.md'),'utf8');
  const tokens=markdown.parse(raw,{});
  const seen=new Map(); const headings=[];
  for(let i=0;i<tokens.length;i++){
    const token=tokens[i];
    if(token.type!=='heading_open') continue;
    const text=tokens[i+1].content;
    const base=text.toLowerCase().replace(/[^\p{L}\p{N}]+/gu,'-').replace(/^-|-$/g,'');
    const n=(seen.get(base)||0)+1; seen.set(base,n);
    const id=base+(n>1?'-'+n:''); token.attrSet('id',id);
    if(token.tag==='h2') headings.push([id,text]);
  }
  const body=markdown.renderer.render(tokens,markdown.options,{});
  const toc=headings.map(([id,text])=>'<li><a href="#'+escape(id)+'">'+escape(text)+'</a></li>').join('');
  const html='<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hunter '+title+' | v'+version+'</title><meta name="description" content="'+escape(description)+'"><meta name="theme-color" content="#123039"><link rel="canonical" href="https://hkjang.github.io/hunter/guides/'+name+'.html"><link rel="icon" href="../assets/favicon.svg"><link rel="stylesheet" href="../assets/guide.css"></head><body><a class="skip" href="#guide-main">본문 바로가기</a><header class="guide-header"><a class="brand" href="../index.html"><img src="../assets/favicon.svg" alt="" width="34" height="34"><strong>hunter.</strong><span>가이드</span></a><nav><a href="'+name+'.md">Markdown</a><a href="'+name+'.pdf">PDF 다운로드</a><a href="../screenshots.html">전체 화면</a></nav></header><div class="guide-layout"><aside class="guide-sidebar"><div>이 문서의 내용</div><ol>'+toc+'</ol><a class="guide-other" href="'+(name==='user-guide'?'admin-guide.html':'user-guide.html')+'">'+(name==='user-guide'?'관리자 가이드':'사용자 가이드')+' →</a></aside><main id="guide-main" class="guide-content">'+body+'<footer>Hunter v'+version+' · 실제 화면과 함께 보는 사내 보안 검증 가이드</footer></main></div></body></html>\n';
  await writeFile(resolve(root,'docs/guides',name+'.html'),html);
  console.log('HTML 생성: '+name);
}
const cards=items=>items.map(([slug,title,description])=>'<figure class="gallery-card"><a href="images/'+slug+'.png"><img src="images/'+slug+'.png" alt="Hunter '+escape(title)+' 실제 화면" width="1512" height="1050" loading="lazy"></a><figcaption><strong>'+escape(title)+'</strong><span>'+escape(description)+'</span>'+(existsSync(resolve(root,'docs/images/mobile-'+slug+'.png'))?'<a href="images/mobile-'+slug+'.png">모바일 화면 보기 →</a>':'')+'</figcaption></figure>').join('');
await writeFile(resolve(root,'docs/screenshots.html'),'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hunter 전체 제품 화면 | 사용자·관리자·개인화</title><meta name="description" content="Hunter의 로그인, 자산, 진단, 발견 건, 관리자 설정과 개인화 전체 실제 화면을 확인하세요."><link rel="canonical" href="https://hkjang.github.io/hunter/screenshots.html"><link rel="icon" href="assets/favicon.svg"><link rel="stylesheet" href="assets/site.css"></head><body><header class="site-header"><a class="brand" href="./"><img src="assets/favicon.svg" width="36" height="36" alt=""><span>hunter.</span></a><nav><a href="./">제품 소개</a><a href="guides/user-guide.html">사용자 가이드</a><a href="guides/admin-guide.html">관리자 가이드</a></nav><a class="header-link" href="./">홈으로 →</a></header><main class="wrap"><div class="gallery-intro"><div class="eyebrow">PRODUCT GALLERY</div><h1>일하는 흐름을 담은,<br>Hunter의 모든 화면.</h1><p>애플리케이션에서 직접 캡처한 '+routes.length+'개 주요 화면과 에이전트 상세 화면의 다섯 탭입니다. 이미지를 선택하면 원본 크기로 볼 수 있습니다. 문서용 예시 데이터는 신규 설치에 자동으로 생성되지 않습니다. 에이전트 응답은 로컬 SSE 모의 모델을 사용한 검증 예시이며 실제 모델 품질이나 취약점 탐지 성능을 나타내지 않습니다.</p></div><div class="gallery-grid">'+cards(routes)+'</div><section aria-labelledby="agent-tabs-title"><div class="gallery-intro"><h2 id="agent-tabs-title">에이전트 상세 화면의 다섯 탭</h2><p>목표부터 도구 호출과 최종 진단까지 단계별 기록을 확인합니다. 각 항목의 모바일 화면도 함께 볼 수 있습니다.</p></div><div class="gallery-grid">'+cards(agentTabs)+'</div></section></main><footer class="site-footer wrap"><a href="guides/user-guide.html">사용자 가이드</a><a href="guides/admin-guide.html">관리자 가이드</a><a href="./">프로젝트 소개</a></footer></body></html>');
await writeFile(resolve(root,'docs/screenshot-manifest.json'),JSON.stringify([...routes,...agentTabs].map(([name,title,description])=>({name,path:'images/'+name+'.png',title,description,...(existsSync(resolve(root,'docs/images/mobile-'+name+'.png'))?{mobile_path:'images/mobile-'+name+'.png'}:{})})),null,2)+'\n');
if(htmlOnly) process.exit(0);
const {chromium}=require('playwright');
const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
try{
  for(const [name,title] of entries){
    const page=await browser.newPage({viewport:{width:1280,height:900}});
    await page.goto(pathToFileURL(resolve(root,'docs/guides',name+'.html')).href,{waitUntil:'networkidle'});
    await page.evaluate(()=>document.fonts.ready);
    const missing=await page.locator('img').evaluateAll(images=>images.filter(i=>!i.complete||i.naturalWidth===0).map(i=>i.getAttribute('src')));
    if(missing.length) throw new Error(name+' 누락된 이미지: '+missing.join(', '));
    await page.pdf({path:resolve(root,'docs/guides',name+'.pdf'),format:'A4',printBackground:true,displayHeaderFooter:true,headerTemplate:'<div></div>',footerTemplate:'<div style="width:100%;font-size:8px;padding:0 38px;color:#61747a;display:flex;justify-content:space-between"><span>Hunter v'+version+' · '+title+'</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',margin:{top:'15mm',bottom:'18mm',left:'14mm',right:'14mm'},tagged:true,outline:true});
    await page.close(); console.log('PDF 생성: '+name);
  }
} finally {await browser.close();}
