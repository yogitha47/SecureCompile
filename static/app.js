const codeInput = document.getElementById('codeInput');
const fileInput = document.getElementById('fileInput');
const analyzeForm = document.getElementById('analyzeForm');
const analyzeButton = document.getElementById('analyzeButton');
const charCount = document.getElementById('charCount');
const statusPill = document.getElementById('statusPill');
const resultSubtitle = document.getElementById('resultSubtitle');
const emptyState = document.getElementById('emptyState');
const errorBox = document.getElementById('errorBox');
const summary = document.getElementById('summary');
const findingsBox = document.getElementById('findings');
const downloadButton = document.getElementById('downloadButton');
const compilerPanel = document.getElementById('compilerPanel');
const memoryPanel = document.getElementById('memoryPanel');
const memoryMap = document.getElementById('memoryMap');
const shareStatus = document.getElementById('shareStatus');
let latestResult = null;

const sample = `#include <stdio.h>\n#include <stdlib.h>\n\nint main(void) {\n    int scores;\n    int sum = 0;\n    for (int i = 0; i <= 5; i++) {\n        scores[i] = rand() % 100;\n        sum += scores[i];\n    }\n    int average = sum / 5;\n    printf("Average: %d\\n", average);\n\n    int *ptr;\n    free(ptr);\n    return 0;\n}`;
function updateCount(){ charCount.textContent = `${codeInput.value.length.toLocaleString()} characters`; }
codeInput.addEventListener('input', updateCount);
document.getElementById('sampleButton').addEventListener('click', () => { codeInput.value = sample; fileInput.value=''; updateCount(); });
fileInput.addEventListener('change', async () => {
  const file = fileInput.files && fileInput.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.c')) { showError('Please choose a .c source file.'); fileInput.value=''; return; }
  codeInput.value = await file.text(); updateCount();
});
function showError(message){ emptyState.hidden = true; errorBox.hidden = false; errorBox.textContent = message; statusPill.className='status-pill bad'; statusPill.textContent='Needs review'; resultSubtitle.textContent='Analysis could not be completed.'; }
function safeText(value){ return String(value ?? ''); }
function lineText(lineNo){ const lines=codeInput.value.split(/\r?\n/); return lines[lineNo-1] || ''; }
function jumpToLine(lineNo){
  const lines=codeInput.value.split(/\r?\n/); const line=Math.max(1,Math.min(Number(lineNo)||1,lines.length));
  const start=lines.slice(0,line-1).reduce((n,s)=>n+s.length+1,0); const end=start+(lines[line-1]||'').length;
  codeInput.focus(); codeInput.setSelectionRange(start,end);
}
function smartFix(f){
  let source=codeInput.value, changed=false;
  if(f.rule_id==='SC-MEM-001') {
    const m=source.match(/\bgets\s*\(\s*(\w+)\s*\)/);
    if(m){ const cap=source.match(new RegExp('\\b(?:char)\\s+'+m[1]+'\\s*\\[\\s*(\\d+)\\s*\\]')); if(cap){source=source.replace(m[0],`fgets(${m[1]}, sizeof(${m[1]}), stdin)`);changed=true;} }
  } else if(f.rule_id==='SC-INPUT-002') {
    const m=source.match(/\bprintf\s*\(\s*([A-Za-z_]\w*)\s*\)/);
    if(m){source=source.replace(m[0],`printf("%s", ${m[1]})`);changed=true;}
  } else if(f.rule_id==='SC-MEM-005') {
    const m=f.message.match(/'([A-Za-z_]\w*)'/);
    if(m){const name=m[1]; const re=new RegExp('\\b(int|char|short|long|float|double)\\s+'+name+'\\s*;'); if(re.test(source)){source=source.replace(re,`$1 ${name}[6];`);changed=true;}}
  }
  if(changed){ if(!confirm('Apply this rule-based edit to the editor? Review the result before using it.')) return; codeInput.value=source;updateCount();shareStatus.textContent='A rule-based edit was applied. Review and re-analyze the code.'; }
  else { alert('No automatic edit is available for this finding because a safe fix depends on buffer sizes, ownership, or program logic. Follow the suggested fix and edit the code manually.'); }
}
function renderCompiler(result){
  compilerPanel.innerHTML=''; compilerPanel.hidden=false;
  const title=document.createElement('h3'); title.textContent='Compiler syntax & type diagnostics'; compilerPanel.appendChild(title);
  const note=document.createElement('p'); note.className='compiler-note'; note.textContent=`${result.compiler?.compiler || 'Compiler frontend'}: ${result.compiler?.note || 'No additional compiler details.'}`; compilerPanel.appendChild(note);
  const ds=result.compiler?.diagnostics||[];
  if(!result.compiler?.available){return;}
  if(!ds.length){const ok=document.createElement('div');ok.className='compiler-clean';ok.textContent='No compiler diagnostics were reported for this source.';compilerPanel.appendChild(ok);return;}
  ds.forEach(d=>{const row=document.createElement('div');row.className=`diagnostic ${d.kind}`;const head=document.createElement('div');head.className='diagnostic-head';head.textContent=`${d.kind.toUpperCase()} · line ${d.line}, column ${d.column}`;const msg=document.createElement('p');msg.textContent=d.message;const expl=document.createElement('p');expl.textContent=d.explanation;const jump=document.createElement('button');jump.className='text-button';jump.textContent='Show line';jump.addEventListener('click',()=>jumpToLine(d.line));row.append(head,msg,expl,jump);compilerPanel.appendChild(row);});
}
function renderMemory(entries){
  memoryMap.innerHTML='';
  if(!entries || !entries.length){memoryPanel.hidden=true;return;}
  memoryPanel.hidden=false;
  entries.forEach(item=>{const card=document.createElement('div');card.className='memory-node';const stack=document.createElement('span');stack.className='memory-kind';stack.textContent='POINTER / STACK';const name=document.createElement('strong');name.textContent=item.name;const arrow=document.createElement('div');arrow.className='memory-arrow';arrow.textContent='↓ points to';const target=document.createElement('div');target.className='memory-target';target.textContent=item.target;const state=document.createElement('p');state.textContent=item.state;card.append(stack,name,arrow,target,state);memoryMap.appendChild(card);});
}
function renderResults(result){
  latestResult = result; errorBox.hidden = true; emptyState.hidden = true; summary.hidden = false; findingsBox.innerHTML=''; downloadButton.hidden = false;
  const counts = result.counts || {};
  summary.innerHTML = `<div class="summary-item high"><strong>${counts.HIGH || 0}</strong><span>HIGH</span></div><div class="summary-item medium"><strong>${counts.MEDIUM || 0}</strong><span>MEDIUM</span></div><div class="summary-item low"><strong>${counts.LOW || 0}</strong><span>LOW</span></div>`;
  resultSubtitle.textContent = `${result.total} security finding${result.total===1?'':'s'} from implemented rules.` + (result.analysis_note ? ` ${result.analysis_note}` : '');
  statusPill.className = `status-pill ${result.total ? 'warn' : 'good'}`; statusPill.textContent = result.total ? 'Review findings' : 'No findings';
  renderCompiler(result); renderMemory(result.memory_model||[]);
  if (!result.findings.length) { findingsBox.innerHTML = '<div class="no-findings"><strong>No security findings from the implemented rules.</strong><br>Compiler diagnostics and security heuristics are separate. A clean result does not guarantee that code is secure.</div>'; return; }
  result.findings.forEach(f => {
    const card = document.createElement('article'); card.className='finding';
    const top=document.createElement('div');top.className='finding-top';
    const title=document.createElement('div'); const h=document.createElement('h3');h.textContent=safeText(f.type); const rule=document.createElement('div');rule.className='rule-line';rule.textContent=`${safeText(f.rule_id)} · Confidence: ${safeText(f.confidence)}`;title.append(h,rule);
    const sev=document.createElement('span');sev.className=`severity ${safeText(f.severity)}`;sev.textContent=safeText(f.severity);top.append(title,sev);card.append(top);
    const message=document.createElement('p');message.textContent=safeText(f.message);card.append(message);
    const explanation=document.createElement('p');explanation.textContent=safeText(f.explanation);card.append(explanation);
    const sourceLine=document.createElement('pre');sourceLine.className='source-line';sourceLine.textContent=f.line ? `${String(f.line).padStart(3,' ')} | ${lineText(f.line).trim()}` : 'Source line unavailable';card.append(sourceLine);
    const fix=document.createElement('div');fix.className='fix';const label=document.createElement('b');label.textContent='Suggested next step';const fixText=document.createElement('span');fixText.textContent=safeText(f.suggestion);fix.append(label,fixText);card.append(fix);
    const actions=document.createElement('div');actions.className='finding-actions';const line=document.createElement('button');line.className='text-button';line.textContent=f.line?`Jump to line ${f.line}`:'Show source';line.addEventListener('click',()=>jumpToLine(f.line));const smart=document.createElement('button');smart.className='text-button';smart.textContent='Try rule-based fix';smart.addEventListener('click',()=>smartFix(f));actions.append(line,smart);card.append(actions);findingsBox.append(card);
  });
}
analyzeForm.addEventListener('submit', async (event) => {
  event.preventDefault(); const file=fileInput.files && fileInput.files[0];
  const data=new FormData(); data.append('code',codeInput.value); if(file) data.append('file',file);
  analyzeButton.disabled=true; analyzeButton.textContent='Analyzing…'; statusPill.className='status-pill idle';statusPill.textContent='Running';
  try { const response=await fetch('/api/analyze',{method:'POST',body:data}); const result=await response.json(); if(!response.ok || !result.ok){showError(result.error || 'Unable to analyze this source.');latestResult=null;downloadButton.hidden=true;summary.hidden=true;findingsBox.innerHTML='';return;} renderResults(result); }
  catch { showError('Could not connect to the local analyzer. Check that the SecureCompile server is running.'); }
  finally { analyzeButton.disabled=false;analyzeButton.innerHTML='Analyze code <span>→</span>'; }
});
downloadButton.addEventListener('click', async () => {
  if (!latestResult) return;
  try { const response=await fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({result:latestResult})}); if(!response.ok) throw new Error(); const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='securecompile_report.json';a.click();URL.revokeObjectURL(url); }
  catch { showError('The report could not be downloaded. Please rerun the analysis and try again.'); }
});
document.getElementById('shareButton').addEventListener('click', async()=>{
  const source=codeInput.value;
  if(!source.trim()){shareStatus.textContent='Add code before creating a share link.';return;}
  if(source.length>5000){shareStatus.textContent='This source is too large for a compact share link (limit 5,000 characters).';return;}
  const bytes=new TextEncoder().encode(source);let binary='';bytes.forEach(b=>binary+=String.fromCharCode(b));const encoded=btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const link=`${location.origin}${location.pathname}#code=${encoded}`;
  try{await navigator.clipboard.writeText(link);shareStatus.textContent='Share link copied. It contains your code in the URL fragment; recipients need access to this website.';}
  catch{shareStatus.textContent='Copy this link: '+link;}
});
function loadCodeFromHash(){
  const match=location.hash.match(/#code=([A-Za-z0-9_-]+)/);if(!match)return;
  try{const b64=match[1].replace(/-/g,'+').replace(/_/g,'/');const binary=atob(b64);const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));codeInput.value=new TextDecoder().decode(bytes);updateCount();shareStatus.textContent='Code loaded from this share link. Run analysis when ready.';}
  catch{shareStatus.textContent='The shared code fragment could not be decoded.';}
}
document.getElementById('batchButton').addEventListener('click',async()=>{
  const input=document.getElementById('batchFiles'),out=document.getElementById('batchResults'),files=Array.from(input.files||[]);
  if(!files.length){out.hidden=false;out.textContent='Select one or more .c files first.';return;}
  out.hidden=false;out.innerHTML='';const title=document.createElement('h3');title.textContent='Multi-file review summary';out.appendChild(title);const rows=[];
  for(const file of files){if(!file.name.toLowerCase().endsWith('.c'))continue;const form=new FormData();form.append('code',await file.text());try{const response=await fetch('/api/analyze',{method:'POST',body:form});const result=await response.json();rows.push({name:file.name,ok:response.ok&&result.ok,total:result.total||0,high:result.counts?.HIGH||0,errors:(result.compiler?.diagnostics||[]).filter(d=>d.kind==='error').length});}catch{rows.push({name:file.name,ok:false,total:0,high:0,errors:0});}}
  if(!rows.length){out.textContent='No .c files were selected.';return;}
  const table=document.createElement('table');table.className='batch-table';const thead=document.createElement('thead');thead.innerHTML='<tr><th>File</th><th>Security findings</th><th>High</th><th>Compiler errors</th><th>Status</th></tr>';table.appendChild(thead);const tbody=document.createElement('tbody');
  rows.forEach(r=>{const tr=document.createElement('tr');[r.name,String(r.total),String(r.high),String(r.errors),r.ok?'Analyzed':'Failed'].forEach(value=>{const td=document.createElement('td');td.textContent=value;tr.appendChild(td);});tbody.appendChild(tr);});table.appendChild(tbody);out.appendChild(table);
});
updateCount();loadCodeFromHash();
