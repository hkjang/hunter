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
const entries=[['user-guide','사용자 가이드','조치함·진단·에이전트 추가 입력·재개·한글 보고서·내 업무 알림·API 키 사용 절차'],['admin-guide','관리자 가이드','폐쇄망 설치, 선택 검색·모델·격리 실행·관측성·GraphQL·자동화·권한·백업 절차']];
const routes=[
['login','로그인','로컬 계정과 SSO 로그인, 서비스 버전'],
['dashboard','보안 현황','서비스와 발견 건의 위험도, 최근 진단'],
['quick-navigation','빠른 이동','현재 권한 안의 메뉴 검색, 즐겨찾기와 최근 방문'],
['quick-navigation-search','빠른 이동 검색','한글 메뉴명·영어 별칭·초성으로 메뉴 찾기'],
['services','서비스 자산','서비스·환경·망·담당자와 공격 표면'],
['findings','발견 건','증거, 위험도, 개선과 재검증 상태'],
['triage','조치함','SLA·위험 점수·위협 정보와 공통 원인 후보'],
['finding-activity','발견 건 활동','댓글·감사 사건·관찰·재검증 정보'],
['software','소프트웨어 명세','서비스별 CycloneDX·SPDX SBOM 반입 이력'],
['software-detail','소프트웨어 명세 상세','구성요소·의존 관계·라이선스 검토와 발견 건'],
['software-compare','소프트웨어 명세 비교','같은 서비스의 구성요소·버전 변화'],
['campaigns','진단 캠페인','목적별 대상 구성과 실제 진단 이력'],
['campaign-detail','캠페인 상세','개별 대상 실행과 진행 상태'],
['campaign-compare','캠페인 결과 비교','동일 조건 내장 실행의 신규·반복·미관측'],
['intelligence','위협 정보','관리자 KEV·EPSS 반입과 자료 기준일'],
['operations','운영 점검','DB·큐·워커·자료 갱신의 읽기 전용 점검'],
['finding-bulk','발견 건 일괄 변경','선택한 항목의 담당자·기한·허용 진행 상태'],
['edit-conflict','편집 충돌 안내','모의 409 응답: 입력 유지와 최신 자료 확인'],
['unsaved-changes','작성 중 입력 보호','입력을 유지하거나 명시적으로 폐기하고 닫기'],
['campaign-copy','같은 대상으로 새 캠페인','합성 자료: 현재 대상 재조회 후 검토하는 새 초안'],
['software-service-view','소프트웨어 서비스 보기','합성 자료: 서비스명 검색과 저장한 서비스 조건'],
['sbom-name-validation','한글 문서명 입력 안내','합성 입력: UTF-8 바이트 수와 초과 전송 차단'],
['notifications-channels','알림 채널','관리자 SMTP·문자·카카오톡·HTTP 채널과 설정 상태'],
['notifications-rules','발송 규칙','이벤트·필터·고정 수신자와 메시지 템플릿'],
['notifications-history','전달 이력','발송 대기·게이트웨이 접수·재시도·결과 확인'],
['notification-channel-smtp','SMTP 채널 설정','사내 릴레이·TLS·인증을 사용하는 합성 설정'],
['notification-channel-http','메시지 API 설정','합성 게이트웨이의 인증·본문·성공 판정 매핑'],
['notification-rule-preview','알림 템플릿 미리보기','외부 발송 없이 합성 값으로 확인하는 메시지'],
['notification-test','채널 테스트 발송','로컬 모의 수신 대상으로 확인하는 명시적 시험'],
['notification-delivery','전달 이력 상세','마스킹 수신자·본문과 시도별 안전한 결과 안내'],
['automation-recipients', '연락처·당직', '합성 연락처와 현재 담당자·당직 기반 수신자 설정'],
['automation-notifications', '알림 자동화 정책', '묶음·한도·영업일·업무 확인·주간 요약 설정'],
['automation-providers', '채널 운영', '공급자 전달 결과·대체 채널·연속 실패 보호'],
['automation-workflows', '변경 영향 규칙', '실제 변경 목록과 일치하는 검사만 선택하는 규칙'],
['automation-tickets', 'ITSM 동기화 규칙', '조회 주소·필드 매핑·배포 재검증·충돌 보호'],
['automation-simulation', '발송 없는 모의 검사', '보관 이벤트를 현재 조건으로 추정한 제외 사유와 건수'],
['automation-history', '자동화 실행 이력', '변경·ITSM의 근거·결과와 연결 진단'],
['automation-retention', '알림 보존 관리', '종결 본문 보존 일수와 파기 예외'],
['personal-inbox', '내 업무 알림', '현재 지정 수신자의 명시적 업무 확인'],
['notification-dynamic-rule', '동적 수신 규칙', '담당자·서비스 소유자·조직·당직 소스 지정'],
['notification-operations-detail', '전달 운영 설정 상세', '합성 게이트웨이의 결과 필드·서명 콜백·채널 보호'],
['list-saved-view','저장한 보기','합성 API 자료: 사용자·메뉴별 목록 조건 저장'],
['list-display-settings','표 표시 설정','합성 API 자료: 행 간격과 표 전체 펼치기'],
['form-validation','입력 오류 안내','모의 저장 실패: 입력 내용 보존과 폼 안의 오류 안내'],
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
["agent-platform-search", "검색 연결", "합성 사내 검색 연결·순차 대체·상태와 명시 시험"],
["agent-platform-memory", "메모리 연결", "로컬 원본 기억과 선택 임베딩·Graphiti·pgvector"],
["agent-platform-models", "모델 연결", "역할별 네이티브 모델 우선순위·한도·상태"],
["agent-platform-execution", "격리 실행 설정", "mTLS 서버·서비스 망·Docker 망·고정 프로브"],
["agent-platform-observability", "관측성 설정", "메타데이터 OTLP·Langfuse와 비동기 상태"],
["agent-platform-model-edit", "모델 설정 편집", "합성 모델 연결·컨텍스트·출력·회복 한도"],
["agent-input", "에이전트 추가 입력", "실행에 반영할 지시와 입력 이력"],
["agent-paused", "에이전트 일시 중지·재개", "안전 경계와 같은 실행의 명시 재개"],
["agent-search-results", "에이전트 참고 검색", "비신뢰 출처 자료와 실제 도구 기록"],
["agent-report", "실행 보고서", "현재 상태의 MD·HTML·한국어 PDF 다운로드"],
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
['admin-settings-sla','조치 기한 설정','SLA 활성화·심각도별 일수·임박 기준'],
['admin-settings-risk','위험 우선순위 설정','KEV·EPSS 가산점과 자료 노후화 기준'],
['admin-settings-inventory','명세 검토 설정','SBOM 갱신 기준과 검토 라이선스 목록'],
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
await writeFile(resolve(root,'docs/screenshots.html'),'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hunter 전체 제품 화면 | 사용자·관리자·개인화</title><meta name="description" content="Hunter의 선택 모델·격리 실행·재개·한국어 보고서와 조치함·캠페인·자동화부터 로그인·관리자 설정·개인화까지 실제 화면을 확인하세요."><link rel="canonical" href="https://hkjang.github.io/hunter/screenshots.html"><link rel="icon" href="assets/favicon.svg"><link rel="stylesheet" href="assets/site.css"></head><body><header class="site-header"><a class="brand" href="./"><img src="assets/favicon.svg" width="36" height="36" alt=""><span>hunter.</span></a><nav><a href="./">제품 소개</a><a href="guides/user-guide.html">사용자 가이드</a><a href="guides/admin-guide.html">관리자 가이드</a></nav><a class="header-link" href="./">홈으로 →</a></header><main class="wrap"><div class="gallery-intro"><div class="eyebrow">PRODUCT GALLERY</div><h1>일하는 흐름을 담은,<br>Hunter의 모든 화면.</h1><p>애플리케이션에서 직접 캡처한 '+routes.length+'개 주요 화면과 에이전트 상세 화면의 다섯 탭입니다. 이미지를 선택하면 원본 크기로 볼 수 있습니다. 문서용 예시 데이터는 신규 설치에 자동으로 생성되지 않습니다. 주요 메뉴·상세·알림센터와 자동화 장면은 v1.8.0 내장 화면에서 갱신했습니다. 알림·자동화 예시와 편집 충돌 장면의 설명용 응답은 브라우저에서 모의 제공했으며 캡처 중 실제 발송이나 업무 자료 변경은 없습니다. 새 에이전트 플랫폼 연동과 실행 제어는 별도 내부 모의 서버를 사용하는 실제 API로 검증했습니다. 저장한 보기·표 표시 설정 장면은 합성 API 응답을, 입력 오류 안내는 모의 저장 실패를 사용해 캡처했습니다. 위협 정보·SBOM·조치함 자료도 설명용 합성 데이터입니다. 알림·자동화 설정과 수신 정보는 합성 값이며 발송·전달 결과·ITSM은 로컬 모의 SMTP·HTTP 서버로 검증했습니다. 실제 공급 계정·단말 수신을 검증한 화면이 아닙니다. 캠페인 비교는 승인된 자체 HTTP 대상에 제한 진단을 실제 실행한 예시이며 전체 취약점 탐지 성능을 뜻하지 않습니다. 에이전트 응답은 로컬 SSE 모의 모델을 사용한 검증 예시이며 실제 모델 품질이나 취약점 탐지 성능을 나타내지 않습니다.</p></div><div class="gallery-grid">'+cards(routes)+'</div><section aria-labelledby="agent-tabs-title"><div class="gallery-intro"><h2 id="agent-tabs-title">에이전트 상세 화면의 다섯 탭</h2><p>목표부터 도구 호출과 최종 진단까지 단계별 기록을 확인합니다. 각 항목의 모바일 화면도 함께 볼 수 있습니다.</p></div><div class="gallery-grid">'+cards(agentTabs)+'</div></section></main><footer class="site-footer wrap"><a href="guides/user-guide.html">사용자 가이드</a><a href="guides/admin-guide.html">관리자 가이드</a><a href="./">프로젝트 소개</a></footer></body></html>');
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
