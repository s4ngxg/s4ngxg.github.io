(()=>{
window.__s4ngxgPageController?.abort();
window.__s4ngxgObserver?.disconnect();
const pageController=new AbortController();
window.__s4ngxgPageController=pageController;
const pageSignal=pageController.signal;

const root=document.documentElement;
const saved=localStorage.getItem('s4ngxg-theme');
const requestedTheme=new URLSearchParams(location.search).get('theme');
const initialTheme=['light','dark'].includes(requestedTheme)?requestedTheme:(saved||'dark');
root.dataset.theme=initialTheme;
const themeButton=document.querySelector('.theme-button');
const themeGlyph=document.querySelector('.theme-glyph');
function syncThemeButton(){
  const dark=root.dataset.theme==='dark';
  if(themeGlyph)themeGlyph.textContent=dark?'☀':'☾';
  if(themeButton)themeButton.setAttribute('aria-label',dark?'Chuyển sang giao diện sáng':'Chuyển sang giao diện tối');
}
syncThemeButton();
themeButton?.addEventListener('click',()=>{const next=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=next;localStorage.setItem('s4ngxg-theme',next);syncThemeButton()});

const menu=document.querySelector('#navLinks');
const menuButton=document.querySelector('.menu-button');
menuButton?.addEventListener('click',()=>{const open=menu.classList.toggle('open');menuButton.setAttribute('aria-expanded',String(open))});
menu?.addEventListener('click',()=>{menu.classList.remove('open');menuButton?.setAttribute('aria-expanded','false')});

const backTop=document.querySelector('.back-top');
if(backTop){addEventListener('scroll',()=>backTop.classList.toggle('visible',scrollY>520),{passive:true,signal:pageSignal});backTop.addEventListener('click',()=>scrollTo({top:0,behavior:'smooth'}))}

const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}}),{threshold:.1});
window.__s4ngxgObserver=observer;
document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));

const archiveParams=new URLSearchParams(location.search);
const selectedCategory=archiveParams.get('category');
const selectedTag=archiveParams.get('tag');
if(selectedCategory||selectedTag){
  document.querySelectorAll('.archive-item').forEach(item=>{
    const tags=(item.dataset.tags||'').split('|');
    item.hidden=selectedCategory?item.dataset.category!==selectedCategory:!tags.includes(selectedTag);
  });
  document.querySelectorAll('.archive-year').forEach(year=>{year.hidden=!year.querySelector('.archive-item:not([hidden])')});
}

document.querySelectorAll('.markdown-content h1[id],.markdown-content h2[id],.markdown-content h3[id],.markdown-content h4[id]').forEach(heading=>{
  if(heading.querySelector(':scope > .heading-anchor'))return;
  const anchor=document.createElement('a');
  anchor.className='heading-anchor';
  anchor.href='#'+encodeURIComponent(heading.id);
  anchor.setAttribute('aria-label','Liên kết đến mục '+heading.textContent.trim());
  anchor.textContent='#';
  heading.append(anchor);
});

document.querySelectorAll('.markdown-content pre').forEach(pre=>{
  if(pre.parentElement?.classList.contains('code-block'))return;
  const wrapper=document.createElement('div');
  wrapper.className='code-block';
  pre.before(wrapper);
  wrapper.append(pre);
  const button=document.createElement('button');
  button.className='copy-code';
  button.type='button';
  button.setAttribute('aria-label','Sao chép đoạn mã');
  button.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path></svg><span>Copy</span>';
  wrapper.append(button);
  button.addEventListener('click',async()=>{
    const code=pre.querySelector('code')?.innerText||pre.innerText;
    try{
      await navigator.clipboard.writeText(code);
      button.classList.add('copied');
      button.querySelector('span').textContent='Đã chép';
      setTimeout(()=>{button.classList.remove('copied');button.querySelector('span').textContent='Copy'},1200);
    }catch{}
  });
});

const tocLinks=[...document.querySelectorAll('.toc-card nav a')];
if(tocLinks.length){
  const tocEntries=tocLinks.map(link=>{
    let id=(link.hash||link.getAttribute('href')||'').replace(/^#/, '');
    try{id=decodeURIComponent(id)}catch{}
    return {link,heading:document.getElementById(id)};
  }).filter(entry=>entry.heading);
  const tocHeadings=tocEntries.map(entry=>entry.heading);
  const tocScroll=document.querySelector('#toc-inner-wrapper');
  const tocIndicator=document.querySelector('.toc-active-indicator');
  let activeId='';
  let hashLockUntil=0;
  const setActive=(id,force=false)=>{
    const activeEntry=tocEntries.find(entry=>entry.heading.id===id);
    if(!activeEntry)return;
    if(!force&&activeId===id)return;
    activeId=id;
    tocEntries.forEach(entry=>entry.link.classList.toggle('active',entry===activeEntry));
    const activeLink=activeEntry.link;
    if(tocIndicator){
      tocIndicator.style.top=activeLink.offsetTop+'px';
      tocIndicator.style.height=activeLink.offsetHeight+'px';
    }
    if(tocScroll){
      const top=activeLink.offsetTop;
      const bottom=top+activeLink.offsetHeight;
      if(top<tocScroll.scrollTop+12)tocScroll.scrollTo({top:Math.max(0,top-24),behavior:'smooth'});
      else if(bottom>tocScroll.scrollTop+tocScroll.clientHeight-12)tocScroll.scrollTo({top:bottom-tocScroll.clientHeight+24,behavior:'smooth'});
    }
  };
  const updateReadingState=()=>{
    if(performance.now()<hashLockUntil)return;
    let current=tocHeadings[0];
    const threshold=Math.min(innerHeight*.28,220);
    tocHeadings.forEach(heading=>{if(heading.getBoundingClientRect().top<=threshold)current=heading});
    if(scrollY+innerHeight>=document.documentElement.scrollHeight-12)current=tocHeadings.at(-1);
    if(current)setActive(current.id);
  };
  const activateHash=()=>{
    if(!location.hash)return false;
    let id=location.hash.slice(1);
    try{id=decodeURIComponent(id)}catch{}
    if(!tocEntries.some(entry=>entry.heading.id===id))return false;
    hashLockUntil=performance.now()+900;
    setActive(id,true);
    return true;
  };
  let tocTicking=false;
  const requestTocUpdate=()=>{
    if(tocTicking)return;
    tocTicking=true;
    requestAnimationFrame(()=>{updateReadingState();tocTicking=false});
  };
  addEventListener('scroll',requestTocUpdate,{passive:true,signal:pageSignal});
  addEventListener('resize',()=>{setActive(activeId,true);requestTocUpdate()},{passive:true,signal:pageSignal});
  addEventListener('hashchange',activateHash,{signal:pageSignal});
  addEventListener('load',()=>requestAnimationFrame(()=>{
    if(!activateHash())requestTocUpdate();
    else setTimeout(activateHash,180);
  }),{once:true});
  updateReadingState();
  if(location.hash)requestAnimationFrame(activateHash);
}

const modal=document.querySelector('.search-modal');
if(modal){
  const input=modal.querySelector('input');
  const results=modal.querySelector('.search-results');
  const posts=[...document.querySelectorAll('[data-search]')].map(post=>({title:post.querySelector('h3').textContent.trim(),meta:post.querySelector('.post-meta')?.textContent.trim().replace(/\s+/g,' ')||'',text:(post.dataset.search+' '+post.textContent).toLowerCase(),href:post.querySelector('h3 a')?.href||'#'}));
  function openSearch(){modal.hidden=false;document.body.classList.add('modal-open');setTimeout(()=>input.focus(),20)}
  function closeSearch(){modal.hidden=true;document.body.classList.remove('modal-open');input.value='';results.innerHTML='<p>Thử tìm “Web3”, “CTF” hoặc “EVM”.</p>'}
  document.querySelector('.search-open')?.addEventListener('click',openSearch);
  document.querySelector('.search-close')?.addEventListener('click',closeSearch);
  modal.addEventListener('click',e=>{if(e.target===modal)closeSearch()});
  document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openSearch()}if(e.key==='Escape'&&!modal.hidden)closeSearch()},{signal:pageSignal});
  input.addEventListener('input',()=>{const q=input.value.trim().toLowerCase();if(!q){results.innerHTML='<p>Thử tìm “Web3”, “CTF” hoặc “EVM”.</p>';return}const found=posts.filter(post=>post.text.includes(q));results.innerHTML=found.length?found.map(post=>`<a class="result" href="${post.href}"><b>${post.title}</b><small>${post.meta}</small></a>`).join(''):'<p>Chưa tìm thấy bài viết phù hợp.</p>'});
}
})();
