const captions = {dashboard:'보안 현황', services:'서비스 자산', findings:'발견 건',triage:'조치함',software:'소프트웨어 명세','campaign-compare':'캠페인 비교','agent-detail':'에이전트 진단','admin-settings':'관리자 설정','personal-keys':'개인 API 키'};
const dialog = document.querySelector('#image-dialog');
const image = document.querySelector('#main-screen');
for(const button of document.querySelectorAll('[data-screen]')){
  button.addEventListener('click',()=>{
    for(const sibling of document.querySelectorAll('[data-screen]')){
      sibling.classList.toggle('active',sibling===button);
      sibling.setAttribute('aria-pressed',String(sibling===button));
    }
    const title=captions[button.dataset.screen];
    image.src='images/'+button.dataset.screen+'.png';
    image.alt='Hunter '+title+' 실제 애플리케이션 화면';
    document.querySelector('#screen-title').textContent=title;
    document.querySelector('#screen-zoom').setAttribute('aria-label',title+' 화면 크게 보기');
  });
}
document.querySelector('#screen-zoom')?.addEventListener('click',()=>{
  const target=document.querySelector('#dialog-image');
  target.src=image.src;target.alt=image.alt;dialog.showModal();
});
document.querySelector('#close-dialog')?.addEventListener('click',()=>dialog.close());
dialog?.addEventListener('click',event=>{if(event.target===dialog)dialog.close();});
