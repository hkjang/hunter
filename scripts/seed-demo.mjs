// Explicit local documentation fixtures. Never invoked by the service or Docker image.
import { readFile, writeFile } from 'node:fs/promises';
const origin = process.argv[2] || 'http://localhost:8080';
if (!['localhost','127.0.0.1'].includes(new URL(origin).hostname)) throw new Error('Documentation fixtures are restricted to a local test service.');
const credentials = JSON.parse(await readFile('.tmp/dev-login.json','utf8'));
const login = await fetch(origin+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json','X-Hunter-CSRF':'1'},body:JSON.stringify(credentials)});
if(!login.ok) throw new Error('Local fixture login failed');
const cookie=login.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
async function api(path,method='GET',body){const response=await fetch(origin+'/api/'+path,{method,headers:{Cookie:cookie,'Content-Type':'application/json','X-Hunter-CSRF':'1'},body:body?JSON.stringify(body):undefined});const data=await response.json();if(!response.ok)throw new Error(`${method} ${path}: ${JSON.stringify(data)}`);return data;}
async function upsert(kind,data){const existing=(await api(kind)).find(r=>data.name&&r.name===data.name||data.title&&r.title===data.title);return existing||api(kind,'POST',data);}
await api('settings/general','PUT',{service_name:'hunter · 예시 환경',public_url:origin});
const services=[];
for(const [name,slug,team,environment,criticality,description] of [
 ['ITSM 업무 포털','itsm','플랫폼팀','staging','tier1','서비스 신청부터 조치까지 연결하는 사내 업무 시스템'],
 ['사내 AI 포털','ai','AI플랫폼팀','staging','tier1','조직별 지식 검색과 업무 AI를 제공하는 서비스'],
 ['API 게이트웨이','gateway','플랫폼팀','production','tier1','업무 API의 인증과 트래픽 정책을 관리합니다'],
 ['Harbor 레지스트리','harbor','DevOps팀','production','tier2','사내 컨테이너 이미지와 배포 산출물 저장소'],
 ['개발자 포털','developer','개발지원팀','development','tier3','개발 가이드와 셀프서비스 카탈로그'],
 ['NL2SQL 스튜디오','nl2sql','데이터팀','staging','tier2','허용된 데이터 범위 내 자연어 데이터 분석']]){
 services.push(await upsert('services',{name,url:`https://${slug}.example.internal`,team,owner:`${team} 담당자`,environment,criticality,description,network:'업무망',approved:environment!=='production',repository:`https://git.example.internal/security/${slug}`,image:`harbor.example.internal/services/${slug}:v1.0.0`,targets:[{type:'api',value:`https://${slug}.example.internal/api`},{type:'database',value:'shared-postgresql'},{type:'component',value:'common-auth-library@2.1'}]}));
}
await upsert('policies',{name:'업무망 기본 안전 정책',description:'예시 정책. 조회 요청과 승인 범위에서만 진단합니다.',enabled:true,max_rps:1,max_concurrency:1,max_requests:10,timeout_seconds:30,allowed_methods:['GET','HEAD'],blocked_paths:['/delete','/payment','/send-sms'],production_active_scan:false});
for (const service of services){await upsert('scopes',{name:service.name+' 검증 범위',service_id:service.id,allowed_hosts:[new URL(service.url).host],allowed_paths:['/'],allowed_cidrs:['10.0.0.0/8'],expires_at:new Date(Date.now()+30*86400000).toISOString(),approved:true,max_rps:1,max_requests:10,timeout_seconds:30});}
const findings=[
 [0,'다른 조직의 신청서 조회 권한 확인 필요','critical','confirmed','common-auth-library@2.1','테스트 사용자 간 데이터 소유 관계가 API 응답에 반영되는지 검증합니다.'],
 [1,'RAG 검색 결과의 부서 필터 누락 의심','high','in_progress','rag-search@1.4','합성 문서로 부서별 검색 범위를 재현했습니다.'],
 [2,'공통 인증 라이브러리의 권한 검사 누락 후보','high','candidate','common-auth-library@2.1','배포 구성과 공통 라이브러리 사용 위치를 확인합니다.'],
 [3,'컨테이너 기본 사용자 권한 점검','medium','in_progress','base-image@3.2','컨테이너 프로세스 권한을 최소화하는 개선안을 검토합니다.'],
 [4,'Content-Security-Policy 헤더 미설정','medium','candidate','web-server','콘텐츠 보안 정책이 누락되어 설정 검토가 필요합니다.'],
 [5,'허용되지 않은 테이블의 질의 실행 검증','high','retest','query-policy@2.0','생성된 SQL의 실행 정책이 허용 범위를 검사하는지 재검증합니다.'],
 [0,'오래된 세션의 로그아웃 후 재사용 점검','medium','candidate','session-manager','종료된 세션을 서버가 거부하는지 검증합니다.'],
 [1,'MCP 도구별 권한 범위 재검증','high','confirmed','mcp-gateway@1.2','제한된 개인 키로 허용되지 않은 도구 요청을 확인합니다.'],
 [3,'이미지 메타데이터의 불필요한 내부 정보','low','candidate','base-image@3.2','불필요한 빌드 경로와 내부 식별자를 제거합니다.'],
 [4,'보안 연락처 정책 문서 개선','info','candidate','documentation','보안 제보 접수 담당자 정보를 최신 상태로 유지합니다.'],
];
const stored=[];
for(const [idx,title,severity,status,component,description] of findings){stored.push(await upsert('findings',{title,service_id:services[idx].id,severity,status,component,source:'manual',description:'[가이드용 합성 예시] '+description,evidence:'[합성 데이터] TEST-USER-A / TEST-USER-B / TEST-DOCUMENT-001을 사용한 예시 기록입니다. 실제 시스템 진단 결과가 아닙니다.',remediation:'서비스의 정책 검사 지점을 확인하고 회귀 테스트를 추가합니다.',assignee:services[idx].owner,due_date:new Date(Date.now()+7*86400000).toISOString(),contribution_points:status==='confirmed'?50:0}));}
for(const service of services.slice(0,4)){const existing=(await api('scans')).find(r=>r.service_id===service.id&&r.profile==='import-only');if(!existing){const scan=await api('scans','POST',{service_id:service.id,profile:'import-only'});await api('imports','POST',{format:'generic',service_id:service.id,scan_id:scan.id,results:[]});}}
const profileA=await upsert('auth-profiles',{name:'합성 사용자 A · 문서 소유자',service_id:services[0].id,type:'bearer',token:'documentation-synthetic-token-a'});
const profileB=await upsert('auth-profiles',{name:'합성 사용자 B · 다른 조직',service_id:services[0].id,type:'bearer',token:'documentation-synthetic-token-b'});
await upsert('scenarios',{name:'신청서 소유자와 타 조직 사용자 비교',service_id:services[0].id,path:'/api/test/requests/TEST-001',authorized_profile_id:profileA.id,unauthorized_profile_id:profileB.id,marker:'TEST-DOCUMENT-001',description:'합성 데이터에서 정상 조회와 비인가 접근을 함께 비교합니다.'});
await upsert('integrations',{name:'ITAM 서비스 카탈로그',type:'rest',endpoint:'https://itam.example.internal/api/services',enabled:false,config:{items_path:'data.services',mapping:{name:'service_name',url:'endpoint',team:'owner_team'}}});
await upsert('integrations',{name:'PostgreSQL 자산 대장',type:'postgres',enabled:false,endpoint:'사내 자산 DB',config:{query:'SELECT name, url, team FROM service_catalog LIMIT 500'}});
const outbound=await upsert('integrations',{name:'ITSM 개선 요청 발신',type:'rest',endpoint:'https://itsm.example.internal/api/tickets',enabled:false,config:{direction:'outbound',template:{title:'{{finding.title}}',description:'{{finding.description}}',external_id:'{{remediation.id}}'}}});
await upsert('integrations',{name:'배포 변경 웹훅',type:'webhook',enabled:true,config:{}});
await upsert('discovery',{name:'신규 인사 서비스',url:'https://hr.example.internal',team:'업무개발팀',owner:'업무개발팀 담당자',environment:'staging',network:'개발망',status:'candidate',criticality:'tier2',description:'[합성 예시] 외부 서비스 카탈로그에서 수집된 등록 후보'});
await upsert('remediations',{name:'공통 인증 권한 검사 개선',finding_id:stored[0].id,service_id:services[0].id,integration_id:outbound.id,description:'[합성 예시] 조직·소유자 권한 확인 로직의 개선 요청 초안',patch:'// 예시 개선 방향\n// Check resource ownership before returning the response.',status:'draft'});
const keys=await api('keys');if(!keys.some(k=>k.name==='문서 예시 · MCP 조회')) await api('keys','POST',{name:'문서 예시 · MCP 조회',scopes:['services:read','findings:read'],expires_days:30});
for(const service of services.slice(0,2)){await upsert('schedules',{name:service.name+' 정기 점검',service_id:service.id,profile:'http-baseline',interval_minutes:60,next_run_at:new Date(Date.now()+3600000).toISOString(),enabled:false});}
await writeFile('.tmp/demo-fixtures.json',JSON.stringify({services,findings:stored},null,2));
console.log(`Created local synthetic guide fixtures: ${services.length} services, ${stored.length} findings. No target scans or outbound messages were sent.`);
