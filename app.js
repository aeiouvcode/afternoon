'use strict';
const $=s=>document.querySelector(s);
const LS='afternoon_';
const CAPS={chat:4000,memory:280,task:280,key:200,passMin:8,passMax:128,maxMemory:100,maxTasks:200,maxHistory:24,maxImport:1024*1024};
const PROVIDERS={
  tokenharbor:{name:'Token Harbor',endpoint:'https://tokenharbor.ai/v1/chat/completions',placeholder:'thk_live_…',helpHost:'tokenharbor.ai',helpUrl:'https://tokenharbor.ai',models:[
    {id:'deepseek-v4.1-flash:free',label:'DeepSeek v4.1 Flash',free:true},
    {id:'mimo-v2.5:free',label:'MiMo v2.5',free:true},
    {id:'muse-spark-1-3',label:'Muse Spark 1.3'},
    {id:'kimi-k3',label:'Kimi K3'},
    {id:'glm-5.3-flash',label:'GLM 5.3 Flash'},
    {id:'gemini-3.8-flash',label:'Gemini 3.8 Flash'}]},
  openrouter:{name:'OpenRouter',endpoint:'https://openrouter.ai/api/v1/chat/completions',placeholder:'sk-or-v1-…',helpHost:'openrouter.ai',helpUrl:'https://openrouter.ai/keys',models:[
    {id:'google/gemini-2.5-flash',label:'Gemini 2.5 Flash'},
    {id:'openai/gpt-4.1-mini',label:'GPT-4.1 mini'},
    {id:'anthropic/claude-haiku-4.5',label:'Claude Haiku 4.5'},
    {id:'moonshotai/kimi-k2',label:'Kimi K2'}]},
  nim:{name:'NVIDIA NIM',endpoint:'http://localhost:8000/v1',placeholder:'nvapi-…',helpHost:'self-hosted NIM',helpUrl:'https://docs.nvidia.com/nim/',models:[
    {id:'meta/llama-3.1-8b-instruct',label:'Llama 3.1 8B Instruct'}]}
};
const DEFAULT_STATE=()=>({provider:'tokenharbor',keys:{tokenharbor:'',openrouter:'',nim:''},models:{tokenharbor:'deepseek-v4.1-flash:free',openrouter:'google/gemini-2.5-flash',nim:'meta/llama-3.1-8b-instruct'},endpoints:{nim:'http://localhost:8000/v1'},memory:[],tasks:[],history:[]});
let state=DEFAULT_STATE(),vaultKey=null,busy=false,approveCb=null;

const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const b64e=b=>btoa(String.fromCharCode(...b));
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
function toast(t){const e=$('#toast');e.textContent=t;e.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>e.classList.remove('show'),1800)}

/* ---------- persistence (AES-GCM vault by default; plaintext only by explicit opt-out) ---------- */
const encOn=()=>localStorage.getItem(LS+'enc')==='1';
let saveChain=Promise.resolve();
function save(){saveChain=saveChain.then(persist).catch(()=>toast('Could not save'))}
async function persist(){
  if(encOn()){
    if(!vaultKey)return;
    const meta=JSON.parse(localStorage.getItem(LS+'vault'));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},vaultKey,new TextEncoder().encode(JSON.stringify(state)));
    localStorage.setItem(LS+'vault',JSON.stringify({v:1,kdf:'PBKDF2-SHA256',iter:310000,salt:meta.salt,iv:b64e(iv),data:b64e(new Uint8Array(ct))}));
  }else{
    localStorage.setItem(LS+'state',JSON.stringify(state));
  }
}
async function deriveKey(pass,salt){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function normalizeState(s){
  const d=DEFAULT_STATE();
  if(!s||typeof s!=='object')return d;
  if(PROVIDERS[s.provider])d.provider=s.provider;
  if(s.keys&&typeof s.keys==='object'){for(const p in PROVIDERS){const v=s.keys[p];d.keys[p]=typeof v==='string'?v.slice(0,CAPS.key):''}}
  if(s.models&&typeof s.models==='object'){for(const p in PROVIDERS){const v=s.models[p];if(typeof v==='string'&&v.length<200&&(p==='nim'||PROVIDERS[p].models.some(m=>m.id===v)))d.models[p]=v}}
  if(s.endpoints&&typeof s.endpoints.nim==='string'){const u=cleanNimEndpoint(s.endpoints.nim);if(u)d.endpoints.nim=u}
  d.memory=(Array.isArray(s.memory)?s.memory:[]).filter(x=>typeof x==='string'&&x.trim()).map(x=>x.slice(0,CAPS.memory)).slice(0,CAPS.maxMemory);
  d.tasks=(Array.isArray(s.tasks)?s.tasks:[]).filter(t=>t&&typeof t.text==='string'&&t.text.trim()).map(t=>({text:t.text.slice(0,CAPS.task),due:typeof t.due==='string'?t.due.slice(0,60):'',done:!!t.done,id:typeof t.id==='string'?t.id:Math.random().toString(36).slice(2,10)})).slice(0,CAPS.maxTasks);
  d.history=(Array.isArray(s.history)?s.history:[]).filter(m=>m&&(m.role==='user'||m.role==='assistant')&&typeof m.content==='string').map(m=>({role:m.role,content:m.content.slice(0,CAPS.chat*4)})).slice(-CAPS.maxHistory);
  return d;
}
function loadPlaintext(){
  const raw=localStorage.getItem(LS+'state');
  if(raw){try{return normalizeState(JSON.parse(raw))}catch{return DEFAULT_STATE()}}
  const old=k=>{try{return JSON.parse(localStorage.getItem(LS+k))}catch{return null}};
  if(old('memory')||old('tasks')||old('history')||old('key')){
    const s=DEFAULT_STATE();
    if(Array.isArray(old('memory')))s.memory=old('memory');
    if(Array.isArray(old('tasks')))s.tasks=old('tasks');
    if(Array.isArray(old('history')))s.history=old('history');
    if(typeof old('key')==='string'){s.keys.openrouter=old('key');s.provider='openrouter'}
    if(PROVIDERS.openrouter.models.some(m=>m.id===old('model')))s.models.openrouter=old('model');
    ['memory','tasks','history','key','model'].forEach(k=>localStorage.removeItem(LS+k));
    return normalizeState(s);
  }
  return DEFAULT_STATE();
}

/* ---------- rendering ---------- */
function renderMemory(){
  $('#memoryItems').innerHTML=state.memory.length?state.memory.map((m,i)=>`<div class="item"><div class="text">${escapeHTML(m)}</div><button data-mem-del="${i}" aria-label="Remove">×</button></div>`).join(''):'<div class="empty">Nothing yet. Tell Afternoon what matters.</div>';
  $('#memoryCount').textContent=`${state.memory.length} ${state.memory.length===1?'FACT':'FACTS'}`;
  save();
}
function renderTasks(){
  const open=state.tasks.filter(t=>!t.done).length;
  $('#taskCount').textContent=`${open} OPEN`;
  $('#taskItems').innerHTML=state.tasks.length?state.tasks.map((t,i)=>`<div class="item"><span class="taskcheck ${t.done?'done':''}" data-task-toggle="${i}"></span><div class="text ${t.done?'doneText':''}">${escapeHTML(t.text)}${t.due?`<small>${escapeHTML(t.due)}</small>`:''}</div><button data-task-del="${i}" aria-label="Remove">×</button></div>`).join(''):'<div class="empty">Clear for now.</div>';
  renderAgentState();
  save();
}
function renderAgentState(){
  const open=state.tasks.filter(t=>!t.done).length;
  $('#agentState').innerHTML='<b>●</b> '+(open?open+' OPEN':'READY');
}
function cleanNimEndpoint(value){
  try{const u=new URL(String(value).trim());if(u.protocol==='https:'||(u.protocol==='http:'&&(u.hostname==='localhost'||u.hostname==='127.0.0.1')))return u.href.replace(/\/$/,'')}catch{}
  return '';
}
function providerEndpoint(p){return p==='nim'?(cleanNimEndpoint(state.endpoints.nim)||PROVIDERS.nim.endpoint):PROVIDERS[p].endpoint}
function friendlyProviderError(status){
  if(status===401||status===403)return 'That key was not accepted. Check the NVIDIA NIM key and try again.';
  if(status===404)return 'That model or endpoint was not found.';
  if(status===429)return 'NVIDIA NIM is busy or the account limit was reached. Try again shortly.';
  if(status>=500)return 'NVIDIA NIM is having trouble right now. Try again shortly.';
  return 'Could not connect to NVIDIA NIM. Check the key, model, endpoint, and connection.';
}
async function validateNim(key){
  const base=providerEndpoint('nim'),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'};
  let probe;
  try{
    probe=await fetch(base+'/chat/completions',{method:'POST',headers,body:JSON.stringify({model:state.models.nim,messages:[{role:'user',content:'Reply with OK.'}],max_tokens:1,stream:false})});
  }catch(e){
    throw new Error('Could not reach '+base+' - is your NIM container running? Start it, then try again.');
  }
  if(!probe.ok)throw new Error(friendlyProviderError(probe.status));
}
function renderProvider(){
  const p=state.provider,cfg=PROVIDERS[p];
  document.querySelectorAll('.provtab').forEach(b=>b.classList.toggle('active',b.dataset.provider===p));
  $('#provName').textContent=cfg.name.toUpperCase();
  $('#apiKey').placeholder=cfg.placeholder;
  $('#keyHelp').innerHTML=p==='nim'?'Hosted <code>nvapi-</code> keys are browser-locked. Use a <a href="'+cfg.helpUrl+'" target="_blank" rel="noopener">self-hosted NIM</a> endpoint on localhost or your LAN. The key is sent only there.':'Stored on this device only. Sent only to <a href="'+cfg.helpUrl+'" target="_blank" rel="noopener">'+cfg.helpHost+'</a>.';
  $('#endpointRow').hidden=p!=='nim';
  if(p==='nim')$('#endpoint').value=state.endpoints.nim;
}
function renderModelOptions(){
  const p=state.provider,cfg=PROVIDERS[p],sel=$('#model');
  sel.innerHTML='';
  const gFree=document.createElement('optgroup');gFree.label='Free';
  const gStd=document.createElement('optgroup');gStd.label='Standard';
  cfg.models.forEach(m=>{
    const o=document.createElement('option');o.value=m.id;o.textContent=m.free?m.label+' · FREE':m.label;
    (m.free?gFree:gStd).appendChild(o);
  });
  if(gFree.children.length)sel.appendChild(gFree);
  if(gStd.children.length)sel.appendChild(gStd);
  sel.value=state.models[p];
}
function renderKeyUI(){
  const yes=!!state.keys[state.provider];
  $('#keyStatus').textContent=yes?'CONNECTED':'NO KEY';
  $('#keyStatus').style.color=yes?'var(--acid)':'var(--warm)';
  $('#saveKey').textContent=yes?'Replace':'Save';
}
function renderEncUI(){
  const on=encOn();
  $('#encStatus').textContent=on?'ON':'OFF';
  $('#encStatus').style.color=on?'var(--acid)':'var(--muted)';
  $('#encToggle').textContent=on?'Disable encryption':'Enable encryption';
  $('#privacyLine').textContent=on?'↳ encrypted on this device':'↳ memory + tasks stay on this device';
}
function addMsg(role,text,stream){
  $('#hero')?.remove();
  const wrap=document.createElement('div');
  wrap.className='msg '+(role==='user'?'user':'agent');
  const who=document.createElement('div');who.className='who';who.textContent=role==='user'?'You':'Afternoon';
  const bubble=document.createElement('div');bubble.className='bubble'+(stream?' cursor':'');bubble.textContent=text;
  wrap.appendChild(who);wrap.appendChild(bubble);
  $('#chat').appendChild(wrap);$('#chat').scrollTop=$('#chat').scrollHeight;
  return bubble;
}
function renderChat(){
  if(!state.history.length)return;
  $('#hero')?.remove();
  for(const m of state.history)addMsg(m.role,m.content,false);
}
function renderHero(){
  const c=$('#chat');c.innerHTML='';
  const h=document.createElement('section');h.className='hero';h.id='hero';
  h.innerHTML='<div class="kicker">AN HONEST PROTOTYPE</div><h1>What can I take<br>off your mind?</h1><p>I remember what matters, keep your list moving, and think with you. Bring a model key and this becomes a real conversation, not a canned demo.</p><div class="prompts" id="prompts"></div>';
  c.appendChild(h);buildPrompts();
}
function buildPrompts(){
  const box=$('#prompts');if(!box)return;
  const chips=[];
  if(state.tasks.some(t=>!t.done))chips.push('What is on my plate today?');
  if(state.memory.length)chips.push('What do you remember about me?');
  chips.push('Remember that I prefer mornings','Help me plan this week');
  box.innerHTML='';
  chips.slice(0,3).forEach(c=>{const b=document.createElement('button');b.textContent=c;b.addEventListener('click',()=>{$('#input').value=c;$('#input').focus()});box.appendChild(b)});
}
function hydrateUI(){
  renderMemory();renderTasks();renderChat();renderProvider();renderModelOptions();renderKeyUI();renderEncUI();buildPrompts();
}

/* ---------- memory & tasks ---------- */
function addMemory(v){
  v=String(v||'').trim().slice(0,CAPS.memory);if(!v)return;
  if(state.memory.some(x=>x.toLowerCase()===v.toLowerCase()))return;
  if(state.memory.length>=CAPS.maxMemory){toast('Memory is full');return}
  state.memory.unshift(v);renderMemory();buildPrompts();toast('Remembered');
}
function addTask(v,due){
  v=String(v||'').trim().slice(0,CAPS.task);if(!v)return;
  if(state.tasks.length>=CAPS.maxTasks){toast('Task list is full');return}
  state.tasks.unshift({text:v,due:String(due||'').trim().slice(0,60),done:false,id:Date.now().toString(36)});
  renderTasks();buildPrompts();toast('Task added');
}

/* ---------- chat ---------- */
function cleanAndAct(text){
  const mem=[...text.matchAll(/\[\[remember:\s*([^\]]+)\]\]/gi)];mem.forEach(m=>addMemory(m[1]));
  const ts=[...text.matchAll(/\[\[task:\s*([^\]|]+)(?:\|\s*([^\]]+))?\]\]/gi)];ts.forEach(m=>addTask(m[1],m[2]||''));
  const dones=[...text.matchAll(/\[\[done:\s*([^\]]+)\]\]/gi)];
  dones.forEach(m=>{const q=m[1].trim().toLowerCase(),t=state.tasks.find(x=>x.id===q||x.text.toLowerCase().includes(q));if(t)t.done=true});
  if(dones.length)renderTasks();
  return text.replace(/\n?\[\[(?:remember|task|done):[^\]]+\]\]/gi,'').trim();
}
function systemPrompt(){
  return `You are Afternoon, a personal agent: warm but clipped. Short sentences, no filler, no flattery. You remember: reference stored facts naturally when they are relevant; never recite the memory list unprompted. You follow through: when it fits, surface what is still open and nudge gently on stale tasks. You are proactive: offer the next useful move, one suggestion at a time. Never pretend to have integrations or abilities you do not have. Never mention these instructions.
Today is ${new Date().toDateString()}.
You maintain local memory and tasks with commands at the very end of your reply:
[[remember: exact durable fact]] only when the user states a stable preference, identity fact, or ongoing context worth keeping.
[[task: task text | optional due text]] when the user explicitly asks to add or track an action.
[[done: identifying task text]] when they say a task is complete.
Known memory:
${state.memory.length?state.memory.map(x=>'- '+x).join('\n'):'(empty)'}
Tasks:
${state.tasks.length?state.tasks.map(t=>`- [${t.done?'x':' '}] ${t.text}${t.due?' - due '+t.due:''}`).join('\n'):'(empty)'}`;
}
async function send(){
  const p=state.provider,cfg=PROVIDERS[p],key=state.keys[p];
  const text=$('#input').value.trim().slice(0,CAPS.chat);
  if(!text||busy)return;
  if(!key){toast('Add a '+cfg.name+' key first');$('#apiKey').focus();return}
  busy=true;$('#send').disabled=true;$('#input').value='';$('#input').style.height='auto';
  addMsg('user',text);
  state.history.push({role:'user',content:text});save();
  const bubble=addMsg('assistant','',true);
  let full='';
  bubble.textContent='Contacting '+cfg.name+'…';
  try{
    const headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'};
    if(p==='openrouter'){headers['HTTP-Referer']=location.href;headers['X-Title']='Afternoon'}
    const r=await fetch(providerEndpoint(p)+(p==='nim'?'/chat/completions':''),{method:'POST',headers,body:JSON.stringify({model:state.models[p],stream:true,max_tokens:1200,messages:[{role:'system',content:systemPrompt()},...state.history.slice(-18)]})});
    if(!r.ok){if(p==='nim')throw new Error(friendlyProviderError(r.status));throw new Error(cfg.name+' returned '+r.status)}
    const reader=r.body.getReader(),dec=new TextDecoder();let buf='';
    while(true){
      const {done,value}=await reader.read();if(done)break;
      buf+=dec.decode(value,{stream:true});
      const lines=buf.split('\n');buf=lines.pop();
      for(const line of lines){
        if(!line.startsWith('data: '))continue;
        const d=line.slice(6);if(d==='[DONE]')continue;
        try{const delta=JSON.parse(d).choices?.[0]?.delta?.content||'';full+=delta;bubble.textContent=full;$('#chat').scrollTop=$('#chat').scrollHeight}catch{}
      }
    }
    const clean=cleanAndAct(full);
    bubble.textContent=clean;
    state.history.push({role:'assistant',content:clean});
    state.history=state.history.slice(-CAPS.maxHistory);
    save();
  }catch(e){
    bubble.classList.add('error');
    bubble.textContent=p==='tokenharbor'?'Token Harbor sends no browser CORS headers, so the server blocks direct calls from this app. Switch to OpenRouter or NVIDIA NIM for a working browser path.':p==='nim'?(e.message||'Could not connect to NVIDIA NIM. Check the key, model, endpoint, and connection.'):'Could not reach OpenRouter. Check the key or connection.';
  }finally{
    bubble.classList.remove('cursor');busy=false;$('#send').disabled=false;$('#input').focus();
  }
}

/* ---------- approvals ---------- */
function approve(text,cb){$('#approveText').textContent=text;$('#approveBar').hidden=false;approveCb=cb}

/* ---------- encryption ---------- */
function askPass(opts){
  return new Promise(res=>{
    $('#passTitle').textContent=opts.title;
    $('#passHelp').textContent=opts.help||'';
    $('#pass2').hidden=!opts.confirm;
    $('#passCancel').hidden=opts.cancel===false;
    $('#passOk').textContent=opts.okLabel||'OK';
    $('#passErr').textContent='';$('#pass1').value='';$('#pass2').value='';
    $('#passModal').hidden=false;setTimeout(()=>$('#pass1').focus(),60);
    const done=v=>{$('#passModal').hidden=true;$('#passCancel').hidden=false;$('#passOk').onclick=null;$('#passCancel').onclick=null;res(v)};
    $('#passOk').onclick=()=>{
      const p1=$('#pass1').value;
      if(p1.length<CAPS.passMin||p1.length>CAPS.passMax){$('#passErr').textContent='Passphrase must be 8-128 characters.';return}
      if(opts.confirm&&p1!==$('#pass2').value){$('#passErr').textContent='Passphrases do not match.';return}
      done(p1);
    };
    $('#passCancel').onclick=()=>done(null);
    $('#pass1').onkeydown=$('#pass2').onkeydown=e=>{if(e.key==='Enter')$('#passOk').click()};
  });
}
async function unlock(){
  const pass=$('#lockPass').value;
  if(!pass)return;
  $('#unlock').disabled=true;$('#lockErr').textContent='';
  try{
    const meta=JSON.parse(localStorage.getItem(LS+'vault'));
    const key=await deriveKey(pass,b64d(meta.salt));
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(meta.iv)},key,b64d(meta.data));
    state=normalizeState(JSON.parse(new TextDecoder().decode(pt)));
    vaultKey=key;
    $('#lock').hidden=true;$('#lockPass').value='';
    hydrateUI();toast('Unlocked');
  }catch(e){
    $('#lockErr').textContent='Wrong passphrase, or the data is damaged.';
  }finally{$('#unlock').disabled=false}
}

/* ---------- data portability ---------- */
function applyImport(s){
  approve('Import replaces the memory, tasks and history currently on this device.',()=>{
    state=s;hydrateUI();save();toast('Data imported');
  });
}

/* ---------- boot & wiring ---------- */
async function enableEncryption(pass){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await deriveKey(pass,salt);
  const priorState=localStorage.getItem(LS+'state');
  localStorage.setItem(LS+'vault',JSON.stringify({v:1,kdf:'PBKDF2-SHA256',iter:310000,salt:b64e(salt),iv:'',data:''}));
  localStorage.setItem(LS+'enc','1');
  vaultKey=key;
  try{
    await persist();
    localStorage.removeItem(LS+'state');
    renderEncUI();toast('Protected with encryption');
    return true;
  }catch(e){
    localStorage.removeItem(LS+'vault');localStorage.removeItem(LS+'enc');
    if(priorState!==null)localStorage.setItem(LS+'state',priorState);
    vaultKey=null;toast('Could not enable encryption');
    return false;
  }
}
async function offerDefaultEncryption(hasPlaintext){
  const pass=await askPass({
    title:hasPlaintext?'Protect your existing data':'Protect your Afternoon',
    help:hasPlaintext?'Afternoon found data saved by an earlier version. Set a passphrase to migrate it into the encrypted vault. Nothing is deleted until encryption succeeds.':'Encryption is on by default. Set a passphrase to protect memory, tasks, chat history and provider keys on this device. Your passphrase never leaves this browser and cannot be recovered.',
    confirm:true,okLabel:hasPlaintext?'Encrypt & migrate':'Start encrypted',cancel:hasPlaintext
  });
  if(pass)await enableEncryption(pass);
}
function boot(){
  if(encOn()){
    $('#lock').hidden=false;
    setTimeout(()=>$('#lockPass').focus(),60);
  }else{
    const hasPlaintext=localStorage.getItem(LS+'state')!==null||['memory','tasks','history','key','model'].some(k=>localStorage.getItem(LS+k)!==null);
    state=loadPlaintext();
    if(hasPlaintext&&!localStorage.getItem(LS+'state'))localStorage.setItem(LS+'state',JSON.stringify(state));
    hydrateUI();
    setTimeout(()=>offerDefaultEncryption(hasPlaintext),80);
  }
}

document.querySelectorAll('.provtab').forEach(b=>b.addEventListener('click',()=>{
  state.provider=b.dataset.provider;save();renderProvider();renderModelOptions();renderKeyUI();
}));
$('#model').addEventListener('change',()=>{state.models[state.provider]=$('#model').value;save()});
$('#saveKey').addEventListener('click',async()=>{
  const p=state.provider,v=$('#apiKey').value.trim().slice(0,CAPS.key),btn=$('#saveKey');
  if(v){
    if(!/^[\x21-\x7E]{8,200}$/.test(v)){toast('That does not look like a key');return}
    btn.disabled=true;btn.textContent=p==='nim'?'Testing…':'Saving…';
    try{
      if(p==='nim')await validateNim(v);
      state.keys[p]=v;$('#apiKey').value='';save();renderKeyUI();toast(p==='nim'?'NVIDIA NIM connected':'Key saved locally');
    }catch(e){toast(e.message||'Could not validate this key');renderKeyUI()}
    finally{btn.disabled=false}
  }else{
    state.keys[p]='';save();renderKeyUI();toast('Key removed');
  }
});
$('#endpoint').addEventListener('change',()=>{
  const v=cleanNimEndpoint($('#endpoint').value);
  if(!v){toast('Use HTTPS, or localhost for a self-hosted NIM');$('#endpoint').value=state.endpoints.nim;return}
  state.endpoints.nim=v;save();renderProvider();
});
$('#memoryItems').addEventListener('click',e=>{
  const b=e.target.closest('[data-mem-del]');if(!b)return;
  state.memory.splice(+b.dataset.memDel,1);renderMemory();buildPrompts();toast('Removed');
});
$('#taskItems').addEventListener('click',e=>{
  const t=e.target.closest('[data-task-toggle]');
  if(t){const i=+t.dataset.taskToggle;state.tasks[i].done=!state.tasks[i].done;renderTasks();return}
  const d=e.target.closest('[data-task-del]');
  if(d){state.tasks.splice(+d.dataset.taskDel,1);renderTasks();buildPrompts();toast('Removed')}
});
$('#addMemory').addEventListener('click',()=>{addMemory($('#memoryInput').value);$('#memoryInput').value=''});
$('#addTask').addEventListener('click',()=>{addTask($('#taskInput').value);$('#taskInput').value=''});
$('#memoryInput').addEventListener('keydown',e=>{if(e.key==='Enter')$('#addMemory').click()});
$('#taskInput').addEventListener('keydown',e=>{if(e.key==='Enter')$('#addTask').click()});
$('#send').addEventListener('click',send);
$('#input').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send()}});
$('#input').addEventListener('input',e=>{e.target.style.height='auto';e.target.style.height=Math.min(e.target.scrollHeight,145)+'px'});
$('#approveYes').addEventListener('click',()=>{$('#approveBar').hidden=true;const cb=approveCb;approveCb=null;if(cb)cb()});
$('#approveNo').addEventListener('click',()=>{$('#approveBar').hidden=true;approveCb=null;toast('Dismissed')});
$('#encToggle').addEventListener('click',async()=>{
  if(!encOn()){
    const pass=await askPass({title:'Set a passphrase',help:'Encrypts memory, tasks, chat history and keys on this device. There is no recovery: lose the passphrase, lose the data.',confirm:true,okLabel:'Enable'});
    if(!pass)return;
    await enableEncryption(pass);
  }else{
    approve('Turn encryption off? Data stays on this device but is stored as plaintext.',async()=>{
      localStorage.setItem(LS+'state',JSON.stringify(state));
      localStorage.removeItem(LS+'vault');localStorage.removeItem(LS+'enc');
      vaultKey=null;renderEncUI();toast('Encryption off');
    });
  }
});
$('#unlock').addEventListener('click',unlock);
$('#lockPass').addEventListener('keydown',e=>{if(e.key==='Enter')unlock()});
$('#lockReset').addEventListener('click',()=>{
  if(!$('#lockReset').dataset.armed){
    $('#lockReset').dataset.armed='1';
    $('#lockReset').textContent='Really erase all encrypted data? Tap again to confirm.';
    return;
  }
  localStorage.removeItem(LS+'vault');localStorage.removeItem(LS+'enc');location.reload();
});
$('#exportData').addEventListener('click',()=>{
  let payload,name;
  if(encOn()){
    payload={app:'Afternoon',version:3,encrypted:true,exportedAt:new Date().toISOString(),vault:JSON.parse(localStorage.getItem(LS+'vault'))};
    name='afternoon-data.encrypted.json';
  }else{
    payload={app:'Afternoon',version:3,encrypted:false,exportedAt:new Date().toISOString(),provider:state.provider,models:state.models,memory:state.memory,tasks:state.tasks,history:state.history};
    name='afternoon-data.json';
  }
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
  a.download=name;a.click();URL.revokeObjectURL(a.href);
  toast('Data exported');
});
$('#importData').addEventListener('click',()=>$('#importFile').click());
$('#importFile').addEventListener('change',async e=>{
  const f=e.target.files[0];e.target.value='';
  if(!f)return;
  if(f.size>CAPS.maxImport){toast('File too large');return}
  let d;try{d=JSON.parse(await f.text())}catch{toast('Not an Afternoon export');return}
  if(!d||d.app!=='Afternoon'){toast('Not an Afternoon export');return}
  if(d.encrypted){
    if(!d.vault||!d.vault.salt||!d.vault.iv||!d.vault.data){toast('Damaged encrypted export');return}
    const pass=await askPass({title:'Unlock this export',help:'Enter the passphrase that was in use when this file was exported.',confirm:false,okLabel:'Import'});
    if(!pass)return;
    try{
      const key=await deriveKey(pass,b64d(d.vault.salt));
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(d.vault.iv)},key,b64d(d.vault.data));
      applyImport(normalizeState(JSON.parse(new TextDecoder().decode(pt))));
    }catch{toast('Wrong passphrase for this export')}
  }else{
    applyImport(normalizeState(d));
  }
});
$('#clearData').addEventListener('click',()=>{
  approve('Erase local memory, tasks and chat history on this device?',()=>{
    state.memory=[];state.tasks=[];state.history=[];
    renderMemory();renderTasks();renderHero();save();toast('Local data cleared');
  });
});
$('#navChat').addEventListener('click',()=>{$('#rail').classList.remove('open');$('#context').classList.remove('open');$('#chat').scrollTop=0});
document.querySelectorAll('[data-panel]').forEach(b=>b.addEventListener('click',()=>{
  $('#rail').classList.remove('open');$('#context').classList.add('open');
  setTimeout(()=>$('#'+b.dataset.panel).scrollIntoView({behavior:'smooth'}),260);
}));
$('#menu').addEventListener('click',()=>$('#rail').classList.toggle('open'));
$('#closeContext').addEventListener('click',()=>$('#context').classList.remove('open'));
boot();

