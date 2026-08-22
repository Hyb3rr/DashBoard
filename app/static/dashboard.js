
const initialTheme=localStorage.getItem('sentinel-theme')||'dark';document.documentElement.dataset.theme=initialTheme;
let ips=[],regions=[],regionDemand=[],ipSummary=null,sortField='last_seen',sortDir='desc',lastFocus=null;
let ipPage=1,ipPageSize=50,ipTotalPages=1,ipCursor=0,deltaBusy=false,realtimeFlushTimer=null,realtimeFlushRunning=false,realtimeFlushPending=false,collectorState='unknown';
let ipsReady=false,regionsReady=false;
const $=id=>document.getElementById(id);
const API_BASE='';
const apiUrl=path=>{if(path.startsWith('/api/')&&!/[?&]mode=/.test(path))path+=`${path.includes('?')?'&':'?'}mode=live`;return API_BASE+path};
const esc=value=>String(value??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
const num=value=>{const n=Number(value);return Number.isFinite(n)?n.toLocaleString('en-US',{maximumFractionDigits:2}).replace(/,/g,' '):'—'};
const isTrue=v=>v===true||v===1||v==='1'||v==='true';
const yes=value=>value===null||value===undefined?'<span class="flag">unknown</span>':isTrue(value)?'<span class="flag on">yes</span>':'<span class="flag">no</span>';

const classification=x=>x.classification?.label||'unknown';
const signalScore=x=>Number(x.threat_signal_score??0);
const classTone=label=>label==='bad'?'bad':label==='watch'?'watch':label==='good'?'good':'unknown';
const networkLocation=x=>x?.network_location&&typeof x.network_location==='object'&&!Array.isArray(x.network_location)?x.network_location:{};
const registrationOf=x=>networkLocation(x).registration&&typeof networkLocation(x).registration==='object'?networkLocation(x).registration:null;
const locationDisputed=x=>Boolean(networkLocation(x).disputed??x?.location_disputed);
const allocationPattern=x=>networkLocation(x).allocation_pattern||'unknown';
const allocationLabel=value=>({cross_region_allocation:'cross-region allocation',consistent:'registration aligned',registration_estimate_only:'RIR estimate only',registration_unavailable:'RIR unavailable',no_operational_evidence:'no operational evidence',unknown:'allocation unknown'})[value]||String(value||'unknown').replaceAll('_',' ');
function locationCell(x){
  const loc=networkLocation(x),reg=registrationOf(x),country=loc.country||x.country||'Unknown',code=loc.country_code||x.country_code||'—',disputed=locationDisputed(x),pattern=allocationPattern(x);
  const city=loc.city||x.city||loc.geo?.city?.value||'';
  const regCode=reg?.country_code||'—',regSource=reg?.source||'RIR';
  const regContext=reg?`<span class="geo-chip registration" title="Registration/ownership context; not an operational location vote">RIR ${esc(regCode)}</span>`:'';
  const countryConflict=Boolean(loc.country_conflict),cityConflict=Boolean(loc.city_conflict);
  const disputeChip=disputed||countryConflict||cityConflict?`<span class="geo-chip disputed" title="${countryConflict?'Country conflict':cityConflict?'City conflict':'Operational location sources disagree'}">${countryConflict?'country conflict':cityConflict?'city conflict':'geo dispute'}</span>`:'';
  const allocation=reg&&pattern==='cross_region_allocation'?`<span class="allocation" title="Operational Geo differs from RIR registration; this alone is not a dispute">${esc(allocationLabel(pattern))}</span>`:'';
  return `<div class="location-cell"><div class="location-primary"><strong title="${esc(country)}">${esc(country)}</strong><span class="geo-chip operational">op geo</span>${disputeChip}</div><span class="secondary-text">${city?`${esc(city)} · `:''}${esc(code)}</span>${reg?`<div class="location-context">${regContext}<span>${esc(regSource)}</span>${allocation}</div>`:''}</div>`;
}
function geoSourceRows(location){
  const breakdown=location?.confidence_breakdown||{},sources=Array.isArray(breakdown.sources)?breakdown.sources:[];
  if(!sources.length)return '<div class="evidence-item">No source-level geo evidence available.</div>';
  return sources.map(item=>{const registration=item.scope==='registration';return `<div class="geo-source-row ${registration?'registration':''}"><span>${esc(item.source||'unknown')} · ${esc(item.country_code||'—')} · ${esc(item.scope||'network')}${registration?' · excluded from operational vote':''}</span><strong>${item.confidence==null?'—':`${num(item.confidence)}%`}</strong></div>`}).join('');
}
function geoSummary(d){
  const loc=networkLocation(d),reg=registrationOf(d),disputed=locationDisputed(d),pattern=allocationPattern(d),country=loc.country||d.country||'Unknown',code=loc.country_code||d.country_code||'—',scope=loc.scope||d.location_scope||'unknown';
  const city=loc.city||d.city||'',lat=loc.latitude??d.latitude,lon=loc.longitude??d.longitude;
  const coordStr=lat!=null&&lon!=null?`${Number(lat).toFixed(4)}, ${Number(lon).toFixed(4)}`:'—';
  const mapUrl=lat!=null&&lon!=null?`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}&zoom=10`:null;
  let note='Operational Geo is resolved from location-capable sources. RIR/WHOIS registration is shown separately and does not vote against operational Geo.';
  let tone='';
  if(loc.country_conflict){note=`Country conflict ${String(loc.country_conflict_severity||'').toUpperCase()}. SAPICS user-country is primary; other datasets disagree.`;tone='warning'}
  else if(loc.city_conflict){note=`City conflict ${String(loc.city_conflict_severity||'').toUpperCase()}. Coordinate distance: ${loc.geo?.city?.distance_km??'—'} km.`;tone='warning'}
  else if(disputed){note='Operational location sources disagree closely enough to mark this result disputed. RIR/WHOIS registration is still excluded from that dispute decision.';tone='warning'}
  else if(pattern==='cross_region_allocation'&&reg){note=`Operational Geo ${code} differs from RIR registration ${reg.country_code||'—'}. This is a cross-region allocation pattern and is not itself a geo dispute.`}
  else if(pattern==='registration_estimate_only'){note='No operational location evidence is available, so the resolver is using RIR registration only as a weak fallback estimate.';tone='warning'}
  const regText=reg?`${reg.country||reg.country_code||'Unknown'} (${reg.country_code||'—'}) · ${reg.source||'RIR'}`:'Unavailable';
  const cityRow=city?`<div class="geo-summary-item"><span>City</span><strong>${esc(city)}</strong></div>`:'';
  const coordRow=`<div class="geo-summary-item"><span>Coordinates</span><strong>${mapUrl?`<a href="${mapUrl}" target="_blank" rel="noopener" style="color:var(--radar);text-decoration:none">${coordStr} ↗</a>`:coordStr}</strong></div>`;
  const ip2=loc.ip2region,ip2Text=ip2&&(ip2.city||ip2.region||ip2.isp)?`${ip2.city||'Unknown'}${ip2.region?` · ${ip2.region}`:''}${ip2.isp?` · ${ip2.isp}`:''}`:null;
  return `<div class="geo-summary"><div class="geo-summary-grid">${cityRow}${coordRow}<div class="geo-summary-item"><span>Operational country</span><strong>${esc(country)} (${esc(code)})</strong></div>${ip2Text?`<div class="geo-summary-item"><span>ip2region context</span><strong>${esc(ip2Text)}</strong></div>`:''}<div class="geo-summary-item"><span>RIR registration</span><strong>${esc(regText)}</strong></div><div class="geo-summary-item"><span>Allocation pattern</span><strong>${esc(allocationLabel(pattern))}</strong></div><div class="geo-summary-item"><span>Location scope</span><strong>${esc(scope)}</strong></div><div class="geo-summary-item"><span>Operational sources</span><strong>${esc((loc.sources||[]).join(', ')||'none')}</strong></div></div><div class="geo-callout ${tone}">${esc(note)}</div><div class="geo-source-list">${geoSourceRows(loc)}</div></div>`;
}
function renderClassificationAnalytics(){
  const counts=ipSummary?.classification||{bad:0,watch:0,good:0,unknown:0};
  const total=Math.max(1,Number(ipSummary?.total_ips||0)), colors={bad:'var(--critical)',watch:'var(--watch)',good:'var(--stable)',unknown:'var(--tertiary)'};
  $('classification-chart').innerHTML=Object.entries(counts).map(([label,count])=>`<div class="risk-chart-row"><label>${label}</label><div class="risk-track"><div class="risk-fill" style="width:${(count/total)*100}%;background:${colors[label]}"></div></div><b>${num(count)}</b></div>`).join('');
  $('ai-scored').textContent=num(ipSummary?.ai?.scored||0);$('ai-flagged').textContent=num(ipSummary?.ai?.flagged||0);$('ai-coverage').textContent=ipSummary?.ai?`${Number(ipSummary.ai.coverage||0).toFixed(2)}%`:'—';
}
function renderRegionAnalytics(){
  const market=regions.filter(x=>x.market_score!=null).sort((a,b)=>Number(b.market_score)-Number(a.market_score)).slice(0,5),maxMarket=Math.max(1,...market.map(x=>Number(x.market_score)));
  $('region-signal-bars').innerHTML=market.length?market.map(x=>`<div class="signal-bar"><label title="${esc(x.country_name)}">${esc(x.country_code)} · <strong>${esc(x.country_name)}</strong></label><div class="risk-track"><div class="risk-fill" style="width:${Number(x.market_score)/maxMarket*100}%;background:var(--radar)"></div></div><b>${num(x.market_score)}</b></div>`).join(''):'<div class="state">No scored market data.</div>';
}
function renderAnalytics(){
  if(ipsReady)renderClassificationAnalytics();
  if(regionsReady)renderRegionAnalytics();
}
function trafficTime(value){return new Date(value).toLocaleString('vi-VN',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}
function trafficClock(value){return new Date(value).toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'})}
function seenTime(value){if(!value)return '—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':date.toLocaleString('vi-VN',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})}
const TRAFFIC_WINDOW_KEY='hub:v2:traffic-window';let trafficRange='1h',trafficStart='',trafficEnd='',trafficFilterType='',trafficFilterValue='',trafficExclude=false;
function localIso(value){return value?new Date(value).toISOString():''}
function localInputValue(iso){const d=new Date(iso);if(Number.isNaN(d.getTime()))return '';const pad=v=>String(v).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`}
function saveTrafficWindow(){try{sessionStorage.setItem(TRAFFIC_WINDOW_KEY,JSON.stringify({range:trafficRange,start:trafficStart,end:trafficEnd,filterType:trafficFilterType,filterValue:trafficFilterValue,exclude:trafficExclude}))}catch(_){} }
function restoreTrafficWindow(){try{const saved=JSON.parse(sessionStorage.getItem(TRAFFIC_WINDOW_KEY)||'null');if(saved){trafficRange=saved.range||trafficRange;trafficStart=saved.start||'';trafficEnd=saved.end||'';trafficFilterType=saved.filterType||'';trafficFilterValue=saved.filterValue||'';trafficExclude=Boolean(saved.exclude)}}catch(_){} }
function syncTrafficInputs(start,end){const startInput=$('traffic-start'),endInput=$('traffic-end');if(startInput&&!startInput.value)startInput.value=localInputValue(start);if(endInput&&!endInput.value)endInput.value=localInputValue(end);$('traffic-window-note').textContent=trafficStart||trafficEnd?'Custom window':'Live window'}
function filterLabel(){return trafficFilterType==='country'?'Country':trafficFilterType==='path'?'Path':'IP'}
function renderTrafficFilter(data){const state=$('traffic-filter-state'),filter=data.filter||null;if(!filter?.type){state.hidden=true;state.innerHTML='';return}state.hidden=false;state.innerHTML=`<strong>${filterLabel()} ${filter.exclude?'≠':'='}</strong><span title="${esc(filter.value)}">${esc(filter.value)}</span><button class="secondary" type="button" id="traffic-filter-clear">Clear filter</button>`;state.querySelector('button').addEventListener('click',clearTrafficFilter)}
function applyTrafficFilter(type,value,exclude){trafficFilterType=type;trafficFilterValue=value;trafficExclude=Boolean(exclude);saveTrafficWindow();loadTraffic(true)}
function clearTrafficFilter(){trafficFilterType='';trafficFilterValue='';trafficExclude=false;saveTrafficWindow();loadTraffic(true)}
function renderTraffic(data){
  let series=(data.series||[]).filter(x=>x.timestamp),chart=$('traffic-chart');
  $('traffic-bucket').textContent=data.bucket||'request buckets';
  $('traffic-summary').textContent=`${num(data.total_requests||0)} requests · ${num(data.error_requests||0)} errors · ${esc(data.range_label||'selected range')} · updated ${trafficClock(data.as_of)}`;
  $('m-requests').textContent=num(data.total_requests||0);$('m-ips').textContent=num(data.unique_ips||0);$('m-countries').textContent=`${num(data.unique_countries||0)} regions observed`;
  renderTrafficFilter(data);
  {
    const w=1000,h=270,padL=52,padR=22,padT=18,padB=34,innerW=w-padL-padR,innerH=h-padT-padB;
    const windowStart=new Date(data.start).getTime(),windowEnd=new Date(data.end).getTime(),rangeMs=Math.max(60000,windowEnd-windowStart);
    if(!Number.isFinite(windowStart)||!Number.isFinite(windowEnd)){chart.innerHTML='<div class="state"><strong>Traffic window unavailable.</strong>Invalid time range.</div>';return}
    if(!series.length){const step=rangeMs/12;series=Array.from({length:13},(_,i)=>({timestamp:new Date(windowStart+i*step).toISOString(),requests:0,errors:0}))}
    const max=Math.max(1,...series.map(x=>Number(x.requests||0)));
    const xFor=t=>padL+Math.max(0,Math.min(1,(new Date(t).getTime()-windowStart)/rangeMs))*innerW;
    const yFor=n=>padT+innerH-(Number(n||0)/max)*innerH;
    const pointValues=series.map(x=>`${xFor(x.timestamp).toFixed(1)},${yFor(x.requests).toFixed(1)}`);const lastPoint=series[series.length-1];if(new Date(lastPoint.timestamp).getTime()<windowEnd)pointValues.push(`${xFor(windowEnd).toFixed(1)},${yFor(0).toFixed(1)}`);const points=pointValues.join(' ');
    const area=`${padL},${padT+innerH} ${points} ${xFor(windowEnd)},${padT+innerH}`;
    const grid=[0,.25,.5,.75,1].map(r=>{const y=padT+innerH-r*innerH;return `<line class="traffic-grid" x1="${padL}" y1="${y}" x2="${w-padR}" y2="${y}"></line><text class="traffic-axis" x="${padL-9}" y="${y+3}" text-anchor="end">${num(Math.round(max*r))}</text>`}).join('');
    const axis=[{x:padL,t:windowStart},{x:padL+innerW/2,t:windowStart+rangeMs/2},{x:w-padR,t:windowEnd}].map((a,i)=>`<text class="traffic-axis" x="${a.x}" y="${h-8}" text-anchor="${i===0?'start':i===2?'end':'middle'}">${i===2&&!trafficEnd?'Now · ':''}${trafficClock(a.t)}</text>`).join('');
    const hitWidth=Math.max(8,Math.min(34,innerW/Math.max(series.length,1)));
    const hits=series.map((x,i)=>`<rect class="traffic-hit" data-index="${i}" x="${Math.max(padL,xFor(x.timestamp)-hitWidth/2)}" y="${padT}" width="${hitWidth}" height="${innerH}" fill="transparent"></rect>`).join('');
    chart.innerHTML=`<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${grid}<line class="traffic-now-line" x1="${w-padR}" y1="${padT}" x2="${w-padR}" y2="${padT+innerH}"></line><polygon class="traffic-area" points="${area}"></polygon><polyline class="traffic-line" points="${points}"></polyline><line id="traffic-guide-line" class="traffic-guide-line" style="display:none"></line><circle id="traffic-guide-dot" class="traffic-guide-dot" style="display:none"></circle>${axis}${hits}</svg><div class="traffic-tooltip" id="traffic-tooltip"></div>`;
    const tooltip=$('traffic-tooltip');chart.querySelectorAll('.traffic-hit').forEach(hit=>{hit.addEventListener('mouseenter',event=>{const item=series[Number(event.currentTarget.dataset.index)],rect=chart.getBoundingClientRect(),x=event.clientX-rect.left,y=event.clientY-rect.top;const cx=xFor(item.timestamp),cy=yFor(item.requests),req=Number(item.requests||0),isPeak=req>=max&&max>0;const guideLine=chart.querySelector('#traffic-guide-line'),guideDot=chart.querySelector('#traffic-guide-dot');if(guideLine&&guideDot){guideLine.setAttribute('x1',cx.toFixed(1));guideLine.setAttribute('y1',padT);guideLine.setAttribute('x2',cx.toFixed(1));guideLine.setAttribute('y2',padT+innerH);guideLine.classList.toggle('at-peak',isPeak);guideLine.style.display='block';guideDot.setAttribute('cx',cx.toFixed(1));guideDot.setAttribute('cy',cy.toFixed(1));guideDot.setAttribute('r',isPeak?6:4.5);guideDot.classList.toggle('at-peak',isPeak);guideDot.style.display='block'};tooltip.innerHTML=`<div class="time">${trafficTime(item.timestamp)}${isPeak?' <span style="color:var(--critical);font-weight:700">· PEAK</span>':''}</div><div class="value"><span>Requests</span><strong>${num(item.requests||0)}</strong></div><div class="value"><span>Errors</span><strong>${num(item.errors||0)}</strong></div>`;tooltip.style.left=`${Math.max(8,Math.min(rect.width-165,x+12))}px`;tooltip.style.top=`${Math.max(8,y-70)}px`;tooltip.classList.add('show')});hit.addEventListener('mouseleave',()=>{tooltip.classList.remove('show');const guideLine=chart.querySelector('#traffic-guide-line'),guideDot=chart.querySelector('#traffic-guide-dot');if(guideLine)guideLine.style.display='none';if(guideDot)guideDot.style.display='none'})});
  }
  const actions=(type,value)=>value?`<span class="row-actions"><button type="button" data-traffic-action="filter" data-filter-type="${type}" data-filter-value="${esc(value)}">Filter</button><button type="button" data-traffic-action="exclude" data-filter-type="${type}" data-filter-value="${esc(value)}">Exclude</button></span>`:'';
  const renderRows=(items,displayFn,type,valueFn=displayFn)=>{const maxValue=Math.max(1,...items.map(x=>Number(x.requests||0)));return items.length?items.map(x=>{const display=displayFn(x),value=valueFn(x),req=Number(x.requests||0),pct=Math.max(3,(req/maxValue)*100);return `<div class="traffic-row"><span class="name" title="${esc(display)}">${esc(display)}</span><span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span><span class="count">${num(x.requests)}</span>${actions(type,value)}</div>`}).join(''):'<div class="state">No data.</div>'};
  const renderIpRows=(items)=>{const maxValue=Math.max(1,...items.map(x=>Number(x.requests||0)));return items.length?items.map(x=>{const req=Number(x.requests||0),pct=Math.max(3,(req/maxValue)*100);return `<div class="traffic-row" tabindex="0" data-traffic-ip="${esc(x.ip)}"><span class="name" title="${esc(x.ip)}">${esc(x.ip)}</span><span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span><span class="count">${num(x.requests)}</span>${actions('ip',x.ip)}</div>`}).join(''):'<div class="state">No data.</div>'};
  $('top-ips').innerHTML=renderIpRows(data.top_ips||[]);
  $('top-paths').innerHTML=renderRows(data.top_paths||[],x=>x.path,'path');
  $('top-countries').innerHTML=renderRows(data.top_countries||[],x=>`${x.country_code||'--'} · ${x.country||'Unknown'}`,'country',x=>x.country_code||'');
}
async function loadTraffic(force=false){
  try{
    const params=new URLSearchParams({range:trafficRange,source:'stream',mode:'live'});
    if(trafficStart)params.set('start',localIso(trafficStart));if(trafficEnd)params.set('end',localIso(trafficEnd));
    if(trafficFilterType){params.set('filter_type',trafficFilterType);params.set('filter_value',trafficFilterValue);if(trafficExclude)params.set('exclude','true')}
    const response=await fetch(apiUrl(`/api/analytics/traffic?${params.toString()}`),{cache:'no-store'});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();syncTrafficInputs(data.start,data.end);saveTrafficWindow();renderTraffic(data);
  }catch(error){$('traffic-chart').innerHTML=`<div class="state"><strong>Traffic analytics unavailable.</strong>${esc(error.message||'Request failed')}</div>`}
}
function applyTrafficWindow(){trafficStart=$('traffic-start').value;trafficEnd=$('traffic-end').value;if(trafficStart&&trafficEnd&&new Date(trafficEnd)<=new Date(trafficStart)){notify('End must be after start');return}saveTrafficWindow();loadTraffic(true)}
function clearTrafficWindow(){trafficStart='';trafficEnd='';$('traffic-start').value='';$('traffic-end').value='';trafficRange='1h';document.querySelectorAll('#traffic-range button').forEach(item=>item.classList.toggle('active',item.dataset.range===trafficRange));saveTrafficWindow();loadTraffic(true)}
let toastTimer=null;
let toastClickTarget=null;
function notify(message,type='info',duration=null,targetIp=null){
  const toast=$('toast');
  if(!toast)return;
  if(toastTimer){clearTimeout(toastTimer);toastTimer=null}
  const isBad=type==='error'||type==='bad'||type==='danger'||type==='critical'||/error|fail|cannot reach|unavailable|bad|critical|alert|reconnecting/i.test(message);
  const isWarn=type==='warn'||type==='warning'||/watch|degraded/i.test(message);
  toast.className='toast';
  if(isBad)toast.classList.add('error');
  else if(isWarn)toast.classList.add('warn');
  else if(type==='success')toast.classList.add('success');
  toastClickTarget=targetIp||null;
  if(toastClickTarget){
    toast.classList.add('clickable');
    toast.innerHTML=`<span>${esc(message)}</span><span class="toast-link-icon">View case ›</span>`;
  }else{
    toast.textContent=message;
  }
  toast.classList.add('show');
  const stayTime=duration||(isBad?5000:isWarn?4000:2500);
  toastTimer=setTimeout(()=>{toast.classList.remove('show');toastTimer=null;toastClickTarget=null},stayTime);
}

function setBusy(busy){$('refresh').disabled=busy}
function applyTheme(theme){document.documentElement.dataset.theme=theme;localStorage.setItem('sentinel-theme',theme);$('theme-toggle').textContent=theme==='dark'?'Light mode':'Dark mode'}
function formatStatusWithDisposition(label, disposition){
  const base=label||'unknown';
  const disp=(typeof disposition==='object'?disposition?.state:disposition)||'';
  if(disp && disp.toLowerCase()!=='new'){
    return `${base} (${disp.toLowerCase()})`;
  }
  return base;
}

function summary(){
  const data=ipSummary||{total_ips:0,classification:{bad:0,watch:0,good:0,unknown:0},privacy:{total:0},priority_items:[]};
  $('m-risk').textContent=num(Number(data.classification?.bad||0)+Number(data.classification?.watch||0));
  $('m-privacy').textContent=num(data.privacy?.total||0);
  renderRiskOverview(data.priority_items||[]);
}
function renderRiskOverview(queue){
  const activeQueue=queue.filter(x=>((typeof x.disposition==='object'?x.disposition?.state:x.disposition)||'new').toLowerCase()!=='resolved');
  $('priority-list').innerHTML=activeQueue.length?activeQueue.map(x=>{const label=classification(x),tone=classTone(label),disp=x.disposition?.state||x.disposition||'new',displayLabel=formatStatusWithDisposition(label,disp),o=x.organization||x.network_type||'Unattributed network',reason=x.classification?.summary||x.classification?.evidence?.[0]||x.observation?.behavior_evidence?.[0]||'No classification evidence';return `<article class="priority-item" tabindex="0" data-ip="${esc(x.ip)}"><div class="priority-score ${tone}">${num(signalScore(x))}</div><div class="priority-ip"><strong>${esc(x.ip)}</strong><span>${esc(o)}</span></div><div class="priority-reason"><strong>${esc(reason)}</strong><span>${esc(x.country||'Unknown')} · ${num(x.requests)} requests</span></div><div class="priority-meta"><strong>${num(x.status_4xx)}</strong><span>4xx responses</span></div><span class="priority-badge ${tone}">${esc(displayLabel)}</span></article>`}).join(''):'<div class="state"><strong>No priority identities</strong>Observed traffic has no unresolved watch or bad classification.</div>';
}

function updateHeaders(){document.querySelectorAll('th.sortable').forEach(th=>{const base=th.textContent.replace(/[ ↓↑]$/,'');th.textContent=base+(sortField===th.dataset.sort?(sortDir==='desc'?' ↓':' ↑'):'');th.classList.toggle('active',th.dataset.sort===sortField)})}
function render(){
  const filtered=ips; $('visible-count').textContent=`${num(ipSummary?.total_ips||filtered.length)} total · page ${ipPage}/${ipTotalPages}`;updateHeaders();
  $('rows').innerHTML=filtered.length?filtered.map(x=>{
  const label=classification(x),level=label==='bad'?'critical':label==='watch'?'medium':label==='good'?'low':'low',score=signalScore(x),ai=x.ai_profile||{},aiKnown=Object.keys(ai).length>0,aiScore=Number(ai.ai_anomaly_score||0),aiTone=aiScore>=70?'alert':aiScore?'':'none',aiWindows=Number(ai.anomalous_windows||0),aiLabel=!aiKnown?'not scored':aiScore?`${aiWindows} anomalous window${aiWindows===1?'':'s'}`:(ai.score_reason||'not flagged'),disp=x.disposition?.state||x.disposition||'new',rowClass=disp==='resolved'?'row-resolved':`row-${label}`,displayStatus=formatStatusWithDisposition(label,disp);
    return `<tr tabindex="0" data-ip="${esc(x.ip)}" class="${esc(rowClass)}"><td><span class="ip mono">${esc(x.ip)}</span><span class="secondary-text">${esc(label)}${disp.toLowerCase()!=='new'?` <span class="disposition-inline ${esc(disp.toLowerCase())}">(${esc(disp.toLowerCase())})</span>`:''}</span></td><td class="mono last-seen" title="${esc(x.last_seen||'—')}">${esc(seenTime(x.last_seen))}</td><td>${locationCell(x)}</td><td class="mono">${num(x.requests)}</td><td class="mono hide-mobile">${num(x.status_4xx)}</td><td class="mono hide-mobile">${num(x.unique_paths)}</td><td>${isTrue(x.is_tor)?'<span class="flag on">tor</span> ':''}${isTrue(x.is_vpn)?'<span class="flag on">vpn</span> ':''}${isTrue(x.is_proxy)?'<span class="flag on">proxy</span> ':''}${isTrue(x.is_hosting)?'<span class="flag">host</span>':''}${![x.is_tor,x.is_vpn,x.is_proxy,x.is_hosting].some(isTrue)?'<span class="flag">unknown</span>':''}</td><td class="ai-cell"><span class="ai-score ${aiTone}">${aiKnown?`${aiScore}/100`:'—'}</span><span class="ai-note">${esc(aiLabel)}${aiKnown&&ai.confidence_level?` · ${esc(ai.confidence_level)}`:''}</span></td><td class="risk-cell"><div class="risk-top"><span class="risk-level ${level}">${esc(displayStatus)}</span><span class="mono">${num(score)}/100</span></div><div class="signal ${level}"><span style="width:${Math.min(100,Math.max(0,score))}%"></span></div></td><td><span class="disp-badge ${esc(disp)}">${esc(disp)}</span></td></tr>`
  }).join(''):'<tr><td colspan="10"><div class="state"><strong>No matching identities</strong>Adjust the search or intelligence filters.</div></td></tr>';



  $('ip-page-label').textContent=`Page ${ipPage} of ${ipTotalPages} · ${num(ipSummary?.total_ips||0)} identities`;
  $('ip-prev').disabled=ipPage<=1;$('ip-next').disabled=ipPage>=ipTotalPages;
}
const IP_SNAPSHOT_KEY='hub:v4:ip-page';let trafficTimer=null,eventSource=null,fallbackPollTimer=null,durableRealtimeTimer=null,sseConnected=false;
function snapshotKey(){return IP_SNAPSHOT_KEY}
function pageQuery(){const params=new URLSearchParams({page:String(ipPage),page_size:String(ipPageSize),sort:sortField,direction:sortDir});const q=$('search').value.trim();if(q)params.set('q',q);if($('privacy').value)params.set('privacy',$('privacy').value);if($('classification').value)params.set('classification',$('classification').value);if($('disposition').value)params.set('disposition',$('disposition').value);return params}
async function loadIpSummary(){try{const response=await fetch(apiUrl('/api/ips/summary'),{cache:'no-store'});if(!response.ok)throw new Error();ipSummary=await response.json();summary();renderAnalytics()}catch(_){} }
function recordRealtimeLatency(items){const renderedAt=Date.now(),event=window.__ipRealtimeLastEvent||{},samples=(items||[]).map(item=>{const p=item.pipeline||{},received=Date.parse(p.received_at||'');if(!Number.isFinite(received))return null;const total=Math.max(0,renderedAt-received),backend=Number(p.backend_ready_ms),published=Date.parse(event.published_at||''),delivered=Number(event.received_at),profiled=Boolean(p.profile_ready_at);return {ip:item.ip,segment:profiled?'profiled':'profile-pending',end_to_end_ms:total,backend_ready_ms:Number.isFinite(backend)?backend:null,publish_to_sse_ms:Number.isFinite(published)&&Number.isFinite(delivered)?Math.max(0,delivered-published):null,delivery_render_ms:Number.isFinite(delivered)?Math.max(0,renderedAt-delivered):null,rendered_at:new Date(renderedAt).toISOString()}}).filter(Boolean);if(!samples.length)return;const history=[...(Array.isArray(window.__ipRealtimeMetrics)?window.__ipRealtimeMetrics:[]),...samples].slice(-200),percentile=(list,p)=>{const ordered=list.map(x=>x.end_to_end_ms).sort((a,b)=>a-b);return ordered.length?ordered[Math.min(ordered.length-1,Math.ceil(ordered.length*p)-1)]:null},profiled=history.filter(x=>x.segment==='profiled'),pending=history.filter(x=>x.segment==='profile-pending'),latest=samples[samples.length-1];window.__ipRealtimeMetrics=history;$('ip-realtime-latency').textContent=`realtime p95 ${num(percentile(history,.95))} ms · profile ${num(percentile(profiled,.95))} · pending ${num(percentile(pending,.95))}`;$('ip-realtime-latency').title=`Latest ${num(latest.end_to_end_ms)} ms · backend ${num(latest.backend_ready_ms)} ms · publish/SSE ${num(latest.publish_to_sse_ms)} ms · render ${num(latest.delivery_render_ms)} ms · ${latest.segment} · ${latest.ip} · ${history.length} samples`}
async function loadIpSnapshot(force=false,realtimeItems=[]){setBusy(true);try{const response=await fetch(apiUrl(`/api/ips/page?${pageQuery()}`),{cache:'no-store'});if(!response.ok)throw new Error(`HTTP ${response.status}`);const data=await response.json();ips=data.items||[];ipPage=Number(data.page||ipPage);ipTotalPages=Math.max(1,Number(data.total_pages||1));ipCursor=Number(data.change_cursor||ipCursor);ipsReady=true;summary();render();recordRealtimeLatency(realtimeItems);renderAnalytics();await loadIpSummary()}catch(error){const message=error instanceof TypeError?'Cannot reach Hub API at http://127.0.0.1:8000. Check that Uvicorn is running.':`Hub API error: ${error.message}`;$('rows').innerHTML=`<tr><td colspan="10"><div class="state"><strong>Intelligence unavailable</strong>${esc(message)}</div></td></tr>`;notify(message)}finally{setBusy(false)}}
function applyIpChanges(items){const known=new Set(ips.map(item=>item.ip));if(items.some(item=>!known.has(item.ip)))return false;const changes=new Map(items.map(item=>[item.ip,item]));ips=ips.map(item=>changes.get(item.ip)||item);render();recordRealtimeLatency(items);loadIpSummary();return true}
async function syncIpDelta(){if(deltaBusy)return false;deltaBusy=true;try{let after=ipCursor,more=true,transitions=[],changedItems=[];while(more){const response=await fetch(apiUrl(`/api/ips/updates?after=${encodeURIComponent(after)}&limit=500`),{cache:'no-store'});if(!response.ok)throw new Error();const data=await response.json();if(data.reset_required){await loadIpSnapshot(true);return true}transitions.push(...(data.transitions||[]));changedItems.push(...(data.items||[]));after=Number(data.cursor||after);more=Boolean(data.has_more);ipCursor=after}if(transitions.length)showRiskTransitions(transitions);if(!changedItems.length)return false;if(!applyIpChanges(changedItems))await loadIpSnapshot(true,changedItems);return true}catch(_){return false}finally{deltaBusy=false}}
function showRiskTransitions(transitions){
  const fresh=transitions.filter(x=>['watch','bad'].includes(x.new_label)&&x.new_label!==x.old_label);
  if(!fresh.length)return;
  const bad=fresh.filter(x=>x.new_label==='bad').length;
  if(fresh.length===1){
    const item=fresh[0];
    const type=item.new_label==='bad'?'bad':'warn';
    notify(`🚨 IP ${item.ip} elevated to ${item.new_label.toUpperCase()}`,type,6000,item.ip);
  }else{
    const targetIp=fresh.find(x=>x.new_label==='bad')?.ip||fresh[0].ip;
    notify(`${fresh.length} new risk changes · ${bad} BAD · ${fresh.length-bad} WATCH`,bad?'bad':'warn',6000,targetIp);
  }
}

function scheduleRealtimeFlush(delay=1000){if(collectorState==='backlog')return;if(realtimeFlushTimer)return;realtimeFlushTimer=setTimeout(async()=>{realtimeFlushTimer=null;if(realtimeFlushRunning){realtimeFlushPending=true;return}realtimeFlushRunning=true;try{if(await syncIpDelta())await loadTraffic(true)}finally{realtimeFlushRunning=false;if(realtimeFlushPending){realtimeFlushPending=false;scheduleRealtimeFlush(0)}}},delay)}
function startDurableRealtimeSync(){if(durableRealtimeTimer)return;durableRealtimeTimer=setInterval(()=>{if(collectorState==='live')scheduleRealtimeFlush(0)},1000)}
function scheduleTrafficRefresh(){if(trafficTimer)return;trafficTimer=window.setTimeout(()=>{trafficTimer=null;loadTraffic(true)},1000)}
function setCollectorStatus(data){const state=data.status||'unknown',previous=collectorState;collectorState=state;$('collector-state').textContent=state==='backlog'?'Replaying log…':state.charAt(0).toUpperCase()+state.slice(1);$('collector-dot').style.background=state==='live'?'var(--stable)':state==='retrying'||state==='config_error'?'var(--hostile)':'var(--watch)';if(state==='live'&&previous==='backlog')scheduleRealtimeFlush()}
function startFallbackPolling(){if(fallbackPollTimer)return;fallbackPollTimer=setInterval(()=>scheduleRealtimeFlush(),5000)}
function stopFallbackPolling(){if(fallbackPollTimer){clearInterval(fallbackPollTimer);fallbackPollTimer=null}}
function startRealtime(){if(!window.EventSource){startFallbackPolling();return}const streamUrl=API_BASE?`${API_BASE}/api/stream`:'/api/stream';try{eventSource=new EventSource(streamUrl)}catch(_){startFallbackPolling();return}eventSource.addEventListener('open',()=>{sseConnected=true;stopFallbackPolling();if(collectorState==='live')scheduleRealtimeFlush(0)});eventSource.addEventListener('ip_changes',event=>{try{window.__ipRealtimeLastEvent={...JSON.parse(event.data),received_at:Date.now()}}catch(_){window.__ipRealtimeLastEvent={received_at:Date.now()}}if(collectorState==='live')scheduleRealtimeFlush(0)});eventSource.addEventListener('collector_status',event=>{try{setCollectorStatus(JSON.parse(event.data))}catch(_){}});eventSource.addEventListener('ai_trained',event=>{try{const data=JSON.parse(event.data);if(data.status)notify(`AI training: ${data.status}`);if(collectorState==='live')scheduleRealtimeFlush(0)}catch(_){}});eventSource.addEventListener('ai_scored',event=>{try{const data=JSON.parse(event.data);if(data.status)notify(`AI scoring: ${data.status}`);if(collectorState==='live')scheduleRealtimeFlush(0)}catch(_){}});eventSource.onerror=()=>{sseConnected=false;startFallbackPolling();$('collector-state').textContent='Reconnecting…';$('collector-dot').style.background='var(--watch)'};fetch(apiUrl('/api/collector/status'),{cache:'no-store'}).then(r=>r.json()).then(setCollectorStatus).catch(()=>{})}
async function loadRegions(){
  const regionRequest=cachedFetch(apiUrl('/api/regions?limit=200'),600000).then(data=>{regions=data;regionsReady=true;renderRegionAnalytics();return data}).catch(()=>{$('region-signal-bars').innerHTML='<div class="state"><strong>Market signals unavailable.</strong>Regions widget failed independently.</div>';return null});
  cachedFetch(apiUrl('/api/regions/demand-signal?limit=24'),45000).then(data=>{regionDemand=data}).catch(()=>{});
  return regionRequest;
}
async function refreshDashboard(){if(window.invalidateHubCache)window.invalidateHubCache();try{sessionStorage.removeItem(IP_SNAPSHOT_KEY)}catch(_){}await Promise.allSettled([loadIpSnapshot(true),loadRegions(),loadTraffic(true)])}
function openDrawer(){lastFocus=document.activeElement;$('drawer').classList.add('open');$('drawer').setAttribute('aria-hidden','false');document.body.style.overflow='hidden';$('drawer').querySelector('button').focus()}
function closeDrawer(){$('drawer').classList.remove('open');$('drawer').setAttribute('aria-hidden','true');document.body.style.overflow='';lastFocus?.focus()}
function evidence(items){return items?.length?items.map(item=>`<div class="evidence-item">${esc(item)}</div>`).join(''):'<div class="evidence-item">No provider evidence available.</div>'}
function evidenceHtml(items){return items?.length?items.map(item=>`<div class="evidence-item">${item}</div>`).join(''):'<div class="evidence-item">No provider evidence available.</div>'}
function providerItems(d){const states=Object.entries(d.provider_status||{}).map(([name,info])=>`${name}: ${info.status}${info.error?` — ${info.error}`:''}`);return states.length?states:[`Sources: ${(d.sources||[]).join(', ')||'none'}`,`Next retry: ${d.next_retry_at||'not scheduled'}`]}
async function detail(ip){
  openDrawer();
  $('detail-title').textContent=ip;
  $('detail-body').innerHTML='<div class="state"><strong>Loading profile…</strong>Correlating network and behavior signals.</div>';
  try{
    const response=await fetch(apiUrl('/api/ip/'+encodeURIComponent(ip)));
    if(!response.ok)throw new Error();
    const d=await response.json(),o=d.observation||{},r=d.region_profile||{},dispObj=d.disposition||{};
    const currentDisp=(dispObj.state||'new').toLowerCase();
    const statusSummary=[`Core: ${d.core_enrichment_status||d.enrichment_status||'unknown'}`,`Privacy: ${d.privacy_enrichment_status||'unknown'}`,`Threat: ${d.threat_enrichment_status||'unknown'}`];
    const networkItems=[`ASN: ${d.asn||'—'}`,`Organization: ${d.organization||'Unattributed'}`,`Prefix: ${d.ip_prefix||'—'}`,`Network type: ${d.network_type||'Unknown'}`];
    const privacyItems=[`Tor: ${yes(d.is_tor)}`,`VPN: ${yes(d.is_vpn)}`,`Proxy: ${yes(d.is_proxy)}`,`Hosting: ${yes(d.is_hosting)}`];
    const threatItems=[`Abuse score: ${d.abuse_score??'Unknown'}`,`Abuse reports: ${d.abuse_reports??'Unknown'}`];
    const classificationItems=[`Label: ${d.classification?.label||'unknown'}`,`Summary: ${d.classification?.summary||'No classification summary'}`,`Confidence: ${d.classification?.confidence??'—'}%`];
    const rareItems=(o.rare_path_evidence||[]).map(x=>`${x.path||'Unknown path'} · rarity ${x.rarity_score??'—'}/100 · first seen ${x.first_seen||'unknown'}`);
    const economicIndicators=Array.isArray(r.economic_indicators)?r.economic_indicators:Object.values((r.economic_indicators||{}).indicators||{});
    const regionItems=[...economicIndicators.map(x=>`${x.label||x.name||'Indicator'}: ${x.value??x.raw_value??'Unknown'}`),...(r.cultural_context||[]).map(x=>`${x.label}: ${x.value}`),...(r.conflict_indicators||[]).map(x=>`${x.label}: ${x.value}`)];
    const sourceItems=Object.entries(d.field_sources||{}).map(([field,source])=>`${field}: ${source}`);
    
    let selectedState=currentDisp;
    const dispThreatLabel=formatStatusWithDisposition(d.threat_signal_label||'unknown',currentDisp);
    const dispClassLabel=formatStatusWithDisposition(d.classification?.label||'unknown',currentDisp);
    $('detail-body').innerHTML=`
      <div class="detail-grid">
        <div class="detail"><span>Threat signal</span><strong>${esc(d.threat_signal_score??0)}/100 · ${esc(dispThreatLabel)}</strong></div>
        <div class="detail"><span>Classification</span><strong>${esc(dispClassLabel)}</strong></div>
        <div class="detail"><span>Core enrichment</span><strong>${esc(d.core_enrichment_status||d.enrichment_status||'unknown')}</strong></div>
        <div class="detail"><span>Privacy enrichment</span><strong>${esc(d.privacy_enrichment_status||'unknown')}</strong></div>
        <div class="detail"><span>Threat enrichment</span><strong>${esc(d.threat_enrichment_status||'unknown')}</strong></div>
        <div class="detail"><span>Identity confidence</span><strong>${esc(d.organization_confidence||0)}%</strong></div>
      </div>

      <div class="section">
        <h3>Case Triage & Disposition</h3>
        <div class="triage-box">
          <div class="triage-states" id="drawer-triage-states">
            ${['new','monitor','investigate','escalate','resolved'].map(st=>`
              <button type="button" class="triage-btn ${st} ${currentDisp===st?'active':''}" data-state="${st}">${st}</button>
            `).join('')}
          </div>
          <div class="triage-form">
            <input type="text" id="drawer-disp-assignee" class="triage-input" placeholder="Assigned analyst (e.g. alex@soc)" value="${esc(dispObj.assigned_to||'')}">
            <input type="text" id="drawer-disp-note" class="triage-input" placeholder="Investigation note / reason..." value="${esc(dispObj.note||'')}">
            <div class="triage-actions">
              <small class="tertiary" id="drawer-disp-updated">${dispObj.updated_at?`Updated: ${seenTime(dispObj.updated_at)}`:'State: '+currentDisp.toUpperCase()}</small>
              <button type="button" class="secondary" id="drawer-disp-save" style="padding:4px 12px;font-size:11px;font-weight:700">Save</button>
            </div>
          </div>
        </div>
      </div>
      <div class="section"><h3>Network location</h3>${geoSummary(d)}</div>
      <div class="section"><h3>Network intelligence</h3><div class="evidence">${evidence(networkItems)}</div></div>
      <div class="section"><h3>Classification</h3><div class="evidence">${evidence([...classificationItems,...(d.classification?.evidence||[])])}</div></div>
      <div class="section"><h3>Region intelligence</h3><div class="evidence">${evidence(regionItems.length?regionItems:['No country profile seeded for this country'])}</div></div>
      <div class="section"><h3>Privacy intelligence</h3><div class="evidence">${evidenceHtml(privacyItems)}</div></div>
      <div class="section"><h3>Threat reputation</h3><div class="evidence">${evidence(threatItems)}</div></div>
      <div class="section"><h3>Observed behavior</h3><div class="detail-grid"><div class="detail"><span>Requests</span><strong>${num(o.requests)}</strong></div><div class="detail"><span>Unique paths</span><strong>${num(o.unique_paths)}</strong></div><div class="detail"><span>4xx responses</span><strong>${num(o.status_4xx)}</strong></div><div class="detail"><span>Sensitive probes</span><strong>${num(o.sensitive_probe_requests)}</strong></div></div></div>
      <div class="section"><h3>Risk assessment</h3><div class="evidence">${evidence([...(d.evidence||[]),...(o.behavior_evidence||[])])}</div></div>
      <div class="section"><h3>Rare path evidence</h3><div class="evidence">${evidence(rareItems.length?rareItems:['No rare path evidence available'])}</div></div>
      <div class="section"><h3>Sources</h3><div class="evidence">${evidence([...statusSummary,...providerItems(d),...sourceItems,`Country profile sources: ${(r.sources||[]).map(x=>x.name).join(', ')||'none'}`,`Next retry: ${d.next_retry_at||'not scheduled'}`])}</div></div>
      <div class="section"><h3>Identity confidence</h3><div class="evidence">${evidence(d.identity_evidence)}</div></div>`;

    document.querySelectorAll('#drawer-triage-states .triage-btn').forEach(btn=>{
      btn.addEventListener('click',()=>{
        selectedState=btn.dataset.state;
        document.querySelectorAll('#drawer-triage-states .triage-btn').forEach(b=>b.classList.toggle('active',b.dataset.state===selectedState));
      });
    });

    $('drawer-disp-save')?.addEventListener('click',async()=>{
      const assignee=$('drawer-disp-assignee')?.value.trim()||null;
      const note=$('drawer-disp-note')?.value.trim()||null;
      const saveBtn=$('drawer-disp-save');
      if(saveBtn)saveBtn.disabled=true;
      try{
        const res=await fetch(apiUrl(`/api/ip/${encodeURIComponent(ip)}/disposition`),{
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({state:selectedState,assigned_to:assignee,note:note,actor:'analyst'})
        });
        if(!res.ok)throw new Error('HTTP '+res.status);
        notify(`IP ${ip} disposition set to ${selectedState.toUpperCase()}`,selectedState==='escalate'?'bad':(selectedState==='investigate'||selectedState==='monitor'?'warn':'success'));
        $('drawer-disp-updated').textContent='Updated just now';
        await loadIpSnapshot(true);
      }catch(err){
        notify('Failed to save disposition: '+err.message,'error');
      }finally{
        if(saveBtn)saveBtn.disabled=false;
      }
    });

  }catch{
    $('detail-body').innerHTML='<div class="state"><strong>Profile unavailable</strong>The enrichment provider did not return this identity.</div>';
  }
}

const viewMeta={overview:{kicker:'Intelligence / Overview',title:'Threat Signal',subtitle:'Operational snapshot of observed traffic, risk and data health.'},threats:{kicker:'Intelligence / Network identities',title:'IP Intelligence',subtitle:'Inspect network identities by behavior, reputation, AI anomaly and region context.'}};
function applyView(){
  const requested=location.hash.replace(/^#/,'')||'overview',view=viewMeta[requested]?requested:'overview',meta=viewMeta[view];
  document.querySelectorAll('[data-view-panel]').forEach(panel=>{panel.hidden=panel.dataset.viewPanel!==view});
  document.querySelectorAll('[data-view]').forEach(link=>{const active=link.dataset.view===view;link.classList.toggle('active',active);if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current')});
  $('page-kicker').textContent=meta.kicker;$('page-title').textContent=meta.title;$('page-subtitle').textContent=meta.subtitle;
}
window.addEventListener('hashchange',applyView);
applyView();
restoreTrafficWindow();document.querySelectorAll('#traffic-range button').forEach(item=>item.classList.toggle('active',item.dataset.range===trafficRange));
 $('theme-toggle').addEventListener('click',()=>applyTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));applyTheme(initialTheme);$('refresh').addEventListener('click',refreshDashboard);let searchTimer=null;['privacy','classification','disposition'].forEach(id=>$(id).addEventListener('input',()=>{ipPage=1;loadIpSnapshot(true)}));$('search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{ipPage=1;loadIpSnapshot(true)},300)});$('classification').addEventListener('input',()=>{document.querySelectorAll('.risk-tab').forEach(tab=>tab.classList.toggle('selected',tab.dataset.classification===$('classification').value));});document.querySelectorAll('#traffic-range button').forEach(button=>button.addEventListener('click',()=>{trafficRange=button.dataset.range;trafficStart='';trafficEnd='';$('traffic-start').value='';$('traffic-end').value='';document.querySelectorAll('#traffic-range button').forEach(item=>item.classList.toggle('active',item===button));saveTrafficWindow();loadTraffic(true)}));
$('traffic-apply').addEventListener('click',applyTrafficWindow);$('traffic-clear').addEventListener('click',clearTrafficWindow);
$('traffic-tables').addEventListener('click',event=>{const action=event.target.closest('[data-traffic-action]');if(!action)return;event.preventDefault();event.stopPropagation();applyTrafficFilter(action.dataset.filterType,action.dataset.filterValue,action.dataset.trafficAction==='exclude')});
document.querySelectorAll('th.sortable').forEach(th=>th.addEventListener('click',()=>{if(sortField===th.dataset.sort)sortDir=sortDir==='desc'?'asc':'desc';else{sortField=th.dataset.sort;sortDir='desc'}ipPage=1;loadIpSnapshot(true)}));
$('ip-prev').addEventListener('click',()=>{if(ipPage>1){ipPage--;loadIpSnapshot(true)}});$('ip-next').addEventListener('click',()=>{if(ipPage<ipTotalPages){ipPage++;loadIpSnapshot(true)}});
document.querySelectorAll('.risk-tab').forEach(tab=>tab.addEventListener('click',()=>{const value=tab.dataset.classification;$('classification').value=value;document.querySelectorAll('.risk-tab').forEach(item=>item.classList.toggle('selected',item===tab));render()}));
const ipHref=ip=>`/ip/${encodeURIComponent(ip)}?mode=live`;
$('rows').addEventListener('click',event=>{const row=event.target.closest('tr[data-ip]');if(row)window.location.href=ipHref(row.dataset.ip)});$('rows').addEventListener('keydown',event=>{const row=event.target.closest('tr[data-ip]');if(row&&(event.key==='Enter'||event.key===' ')){event.preventDefault();window.location.href=ipHref(row.dataset.ip)}});
 $('top-ips').addEventListener('click',event=>{if(event.target.closest('[data-traffic-action]'))return;const row=event.target.closest('[data-traffic-ip]');if(row)window.location.href=ipHref(row.dataset.trafficIp)});$('top-ips').addEventListener('keydown',event=>{const row=event.target.closest('[data-traffic-ip]');if(row&&(event.key==='Enter'||event.key===' ')){event.preventDefault();window.location.href=ipHref(row.dataset.trafficIp)}});
const openIp=ip=>{window.location.href=ipHref(ip)};
document.querySelector('#priority-list').addEventListener('click',event=>{const row=event.target.closest('[data-ip]');if(row)openIp(row.dataset.ip)});
document.querySelector('#priority-list').addEventListener('keydown',event=>{const row=event.target.closest('[data-ip]');if(row&&(event.key==='Enter'||event.key===' ')){event.preventDefault();openIp(row.dataset.ip)}});
let latestHealth=null;
async function fetchHealthStatus(notifyUser=false){
  try{
    const res=await fetch(apiUrl('/health'),{cache:'no-store'});
    if(!res.ok)throw new Error('Health check failed: '+res.status);
    const data=await res.json();
    latestHealth=data;
    if(data.collector)setCollectorStatus(data.collector);
    renderHealthWidget(data);
    if($('health-dialog')?.classList.contains('open')){
      renderHealthDialog(data);
    }
    if(notifyUser)notify('Health check completed: '+(data.status==='ok'?'All systems nominal':'Degraded state'));
  }catch(err){
    renderHealthWidgetError(err);
  }
}
function updateChip(id,isOk,overrideClass){
  const el=$(id);
  if(!el)return;
  el.classList.remove('ok','warn','err');
  el.classList.add(overrideClass||(isOk?'ok':'err'));
}
function renderHealthWidget(data){
  const isHealthy=data.status==='ok';
  const pgOk=data.storage?.postgres?.status==='ok';
  const chOk=data.storage?.clickhouse?.status==='ok';
  const rulesOk=data.rules?.status==='ok';
  const streamState=data.collector?.status||collectorState||'unknown';
  const streamOk=streamState==='live';
  $('collector-state').textContent=isHealthy?(streamState==='live'?'Live Stream':(streamState==='backlog'?'Replaying':'Healthy')):'Degraded';
  $('collector-dot').style.background=isHealthy?'var(--stable)':'var(--watch)';
  updateChip('chip-pg',pgOk);
  updateChip('chip-ch',chOk);
  updateChip('chip-rules',rulesOk);
  updateChip('chip-stream',streamOk,streamState==='backlog'?'warn':(streamOk?'ok':'err'));
}
function renderHealthWidgetError(err){
  $('collector-state').textContent='Unreachable';
  $('collector-dot').style.background='var(--critical)';
  ['chip-pg','chip-ch','chip-rules','chip-stream'].forEach(id=>updateChip(id,false,'err'));
}
function renderHealthDialog(data){
  if(!data)return;
  const pg=data.storage?.postgres||{},ch=data.storage?.clickhouse||{},rules=data.rules||{},col=data.collector||{};
  $('health-last-checked').textContent='Last checked: '+new Date().toLocaleTimeString();
  $('health-dialog-body').innerHTML=`
    <div class="health-svc-card">
      <div class="health-svc-head">
        <div class="health-svc-title"><span class="dot-sm" style="background:${data.status==='ok'?'var(--stable)':'var(--watch)'}"></span>Overall Cluster Status</div>
        <span class="health-svc-badge ${data.status==='ok'?'ok':'warn'}">${esc(data.status)}</span>
      </div>
      <div class="health-svc-details">
        <div class="health-svc-detail"><span>Architecture Mode</span><strong>${esc(data.mode||'split')}</strong></div>
        <div class="health-svc-detail"><span>Cluster Health</span><strong>${data.status==='ok'?'All systems nominal':'Degraded state'}</strong></div>
      </div>
    </div>
    <div class="health-svc-card">
      <div class="health-svc-head">
        <div class="health-svc-title"><span class="dot-sm" style="background:${pg.status==='ok'?'var(--stable)':'var(--critical)'}"></span>PostgreSQL (State & Relational)</div>
        <span class="health-svc-badge ${pg.status==='ok'?'ok':'err'}">${esc(pg.status||'unknown')}</span>
      </div>
      <div class="health-svc-details">
        <div class="health-svc-detail"><span>Role</span><strong>State & Profiles DB</strong></div>
        <div class="health-svc-detail"><span>Connection</span><strong>${pg.status==='ok'?'Active / Connected':esc(pg.error||'Disconnected')}</strong></div>
      </div>
    </div>
    <div class="health-svc-card">
      <div class="health-svc-head">
        <div class="health-svc-title"><span class="dot-sm" style="background:${ch.status==='ok'?'var(--stable)':'var(--critical)'}"></span>ClickHouse (Events & Analytics)</div>
        <span class="health-svc-badge ${ch.status==='ok'?'ok':'err'}">${esc(ch.status||'unknown')}</span>
      </div>
      <div class="health-svc-details">
        <div class="health-svc-detail"><span>Role</span><strong>High-throughput Log Store</strong></div>
        <div class="health-svc-detail"><span>Connection</span><strong>${ch.status==='ok'?'Active / Connected':esc(ch.error||'Disconnected')}</strong></div>
      </div>
    </div>
    <div class="health-svc-card">
      <div class="health-svc-head">
        <div class="health-svc-title"><span class="dot-sm" style="background:${rules.status==='ok'?'var(--stable)':'var(--critical)'}"></span>Detection Rules Engine</div>
        <span class="health-svc-badge ${rules.status==='ok'?'ok':'err'}">${esc(rules.status||'unknown')}</span>
      </div>
      <div class="health-svc-details">
        <div class="health-svc-detail"><span>Active Rules</span><strong>${rules.rule_count??14} rules active</strong></div>
        <div class="health-svc-detail"><span>Ruleset Hash</span><strong>${rules.ruleset_hash?esc(rules.ruleset_hash.slice(0,12))+'…':'—'}</strong></div>
      </div>
    </div>
    <div class="health-svc-card">
      <div class="health-svc-head">
        <div class="health-svc-title"><span class="dot-sm" style="background:${col.status==='live'?'var(--stable)':(col.status==='backlog'?'var(--watch)':'var(--critical)')}"></span>Log Stream (WebSocket Ingest)</div>
        <span class="health-svc-badge ${col.status==='live'?'ok':(col.status==='backlog'?'warn':'err')}">${esc(col.status||'unknown')}</span>
      </div>
      <div class="health-svc-details">
        <div class="health-svc-detail"><span>Source ID</span><strong>${esc(col.source_id||'azure-access')}</strong></div>
        <div class="health-svc-detail"><span>Stream Offset</span><strong>${col.offset!==undefined?num(col.offset):'—'}</strong></div>
      </div>
    </div>
  `;
}
function openHealthDialog(){
  $('health-dialog').classList.add('open');
  $('health-dialog').setAttribute('aria-hidden','false');
  if(latestHealth)renderHealthDialog(latestHealth);
  fetchHealthStatus();
}
function closeHealthDialog(){
  $('health-dialog').classList.remove('open');
  $('health-dialog').setAttribute('aria-hidden','true');
}
document.querySelectorAll('[data-close]').forEach(el=>el.addEventListener('click',closeDrawer));
$('health-widget')?.addEventListener('click',openHealthDialog);
$('health-widget')?.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openHealthDialog()}});
$('close-health-btn')?.addEventListener('click',closeHealthDialog);
$('recheck-health-btn')?.addEventListener('click',()=>fetchHealthStatus(true));
$('health-dialog')?.addEventListener('click',e=>{if(e.target===$('health-dialog'))closeHealthDialog()});
document.addEventListener('keydown',event=>{
  if(event.key==='Escape'){
    if($('health-dialog')?.classList.contains('open'))closeHealthDialog();
    if($('drawer').classList.contains('open'))closeDrawer();
  }
});
$('toast')?.addEventListener('click',()=>{
  if(toastClickTarget){
    window.location.href=`/ip/${encodeURIComponent(toastClickTarget)}?mode=live`;
  }
});
loadIpSnapshot();loadRegions();loadTraffic();startRealtime();startDurableRealtimeSync();fetchHealthStatus();
setInterval(fetchHealthStatus,10000);

