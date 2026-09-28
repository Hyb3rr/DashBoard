(() => {
  const list = document.getElementById('alerts-list');
  const state = document.getElementById('alerts-state');
  const status = document.getElementById('alert-status');
  const timeFilter = document.getElementById('alert-time');
  let selectedRange = '24h';
  let customStart = '';
  let customEnd = '';
  const autoExplainToggle = document.getElementById('auto-explain-toggle');
  const loadMoreButton = document.getElementById('alerts-load-more');
  let busy = false;
  let loadGeneration = 0;
  let nextCursor = null;
  let renderedItems = [];

  const themeButton = document.getElementById('theme-toggle');
  const savedTheme = localStorage.getItem('sentinel-theme') || 'dark';
  document.documentElement.dataset.theme = savedTheme;
  const applyTheme = theme => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('sentinel-theme', theme);
    themeButton.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
  };
  applyTheme(savedTheme);
  themeButton.addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const when = value => window.formatVnTime ? window.formatVnTime(value) : (value ? new Date(value).toLocaleString() : '—');
  const label = value => String(value || '').replace(/^./, ch => ch.toUpperCase());
  const severityRank = {low: 1, medium: 2, critical: 3};

  function selectCurrentCaseAlerts(items) {
    const casesByIp = new Map();
    items.forEach(item => {
      const key = String(item.ip || '');
      if (!key) return;
      const current = casesByIp.get(key);
      const rank = severityRank[item.severity] || 0;
      const currentRank = severityRank[current?.severity] || 0;
      const createdAt = Date.parse(item.created_at || '') || 0;
      const currentCreatedAt = Date.parse(current?.created_at || '') || 0;
      const isNewer = createdAt > currentCreatedAt ||
        (createdAt === currentCreatedAt && Number(item.id) > Number(current?.id));
      if (!current || rank > currentRank || (rank === currentRank && isNewer)) {
        casesByIp.set(key, item);
      }
    });
    return [...casesByIp.values()];
  }

  function alertBehavior(item) {
    const evidence = Array.isArray(item.evidence) ? item.evidence : [];
    const signals = evidence.map(entry => {
      if (typeof entry === 'string') return entry;
      if (!entry || typeof entry !== 'object') return '';
      const observed = entry.observed || {};
      return [entry.type, entry.source, observed.rule_id, observed.rule_name, entry.description,
        JSON.stringify(observed)].filter(Boolean).join(' ');
    }).filter(Boolean);
    const text = signals.join(' ').toLowerCase();
    if (/sensitive|\.env|wp-config|web-sensitive/.test(text)) return 'Sensitive path probing';
    if (/brute|wp.login|web-brute/.test(text)) return 'Brute-force login attempts';
    if (/rare.path|rare_path/.test(text)) return 'Rare path activity';
    if (/enumerat|path.scan|web-scan/.test(text)) return 'Path enumeration';
    if (/request.burst|web-burst/.test(text)) return 'Request burst';
    if (/repeated.client.errors|web-4xx/.test(text)) return 'Repeated client errors';
    if (/bot.repeated.errors|web-bot/.test(text)) return 'Automated requests with repeated errors';
    if (/sustained.request.rate|web-rate/.test(text)) return 'High request rate';
    const networkSignals = [];
    if (/\bproxy\b/.test(text)) networkSignals.push('Proxy');
    if (/\bvpn\b/.test(text)) networkSignals.push('VPN');
    if (/\btor\b/.test(text)) networkSignals.push('Tor exit');
    if (/hosting|datacenter/.test(text)) networkSignals.push('Hosting/datacenter');
    if (networkSignals.length) return `${networkSignals.join(' + ')} network`;
    if (item.reason_type === 'critical_recurrence') return 'Critical activity repeated';
    return 'Security risk signals';
  }

  function alertCard(item) {
    const behavior = alertBehavior(item);
    const evidenceTitle = (Array.isArray(item.evidence) ? item.evidence : [])
      .map(entry => typeof entry === 'string' ? entry : entry?.description || entry?.observed?.rule_name || '')
      .filter(Boolean).join(' · ');
    return `
      <article class="alert-card ${esc(item.severity)} ${esc(item.status)}" data-alert-id="${esc(item.id)}" data-ip="${esc(item.ip)}" tabindex="0" role="link" aria-label="Open details for ${esc(item.ip)}">
        <div class="alert-card-head">
          <time datetime="${esc(item.created_at || '')}">${esc(when(item.created_at))}</time>
        </div>
        <div class="alert-card-body">
          <div class="alert-card-content"><h3 title="${esc(item.ip)}">${esc(item.ip)}</h3><div class="alert-reason"><span>Detected behavior</span><strong title="${esc(evidenceTitle || behavior)}">${esc(behavior)}</strong></div></div>
        </div>
      </article>`;
  }

  function render(items) {
    const cutoffHours = {'1h': 1, '6h': 6, '12h': 12, '24h': 24, '7d': 24 * 7, '30d': 24 * 30}[selectedRange];
    const visibleItems = cutoffHours ? items.filter(item => {
      const created = Date.parse(item.created_at || '');
      return Number.isFinite(created) && Date.now() - created <= cutoffHours * 60 * 60 * 1000;
    }) : items.filter(item => { const stamp = Date.parse(item.created_at || ''); return (!customStart || stamp >= Date.parse(customStart)) && (!customEnd || stamp <= Date.parse(customEnd)); });
    const currentCases = selectCurrentCaseAlerts(visibleItems)
      .filter(item => !status.value || item.status === status.value);
    const grouped = {low: [], medium: [], critical: []};
    currentCases.forEach(item => { if (grouped[item.severity]) grouped[item.severity].push(item); });
    Object.entries(grouped).forEach(([level, levelItems]) => {
      const column = list.querySelector(`[data-alert-items="${level}"]`);
      const count = list.querySelector(`[data-alert-count="${level}"]`);
      if (count) count.textContent = String(levelItems.length);
      if (column) column.innerHTML = levelItems.length ? levelItems.map(alertCard).join('') : '<div class="state">No alerts</div>';
    });
    list.querySelectorAll('[data-status]').forEach(button => button.addEventListener('click', async () => {
      const card = button.closest('.alert-card');
      const id = card?.dataset.alertId;
      if (!id) return;
      button.disabled = true;
      try {
        const response = await fetch(`/api/alerts/${encodeURIComponent(id)}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: button.dataset.status})});
        if (!response.ok) throw new Error('update failed');
        await load();
      } catch (_) {
        button.disabled = false;
        state.textContent = 'Alert update failed';
      }
    }));
    list.querySelectorAll('.alert-card').forEach(card => {
      const open = () => { window.location.href = `/ip/${encodeURIComponent(card.dataset.ip)}?mode=live`; };
      card.addEventListener('click', event => { if (!event.target.closest('button')) open(); });
      card.addEventListener('keydown', event => { if ((event.key === 'Enter' || event.key === ' ') && !event.target.closest('button')) { event.preventDefault(); open(); } });
    });
  }

  function renderItems(items) {
    renderedItems = items;
    render(items);
  }

  function renderAutoExplain(enabled) {
    autoExplainToggle.disabled = false;
    autoExplainToggle.setAttribute('aria-pressed', String(enabled));
    autoExplainToggle.textContent = enabled ? 'ON' : 'OFF';
    autoExplainToggle.classList.toggle('active', enabled);
  }

  async function loadAutoExplainSetting() {
    try {
      const response = await fetch('/api/alerts/settings', {cache: 'no-store'});
      if (!response.ok) throw new Error('settings unavailable');
      renderAutoExplain(Boolean((await response.json()).critical_alert_auto_explain));
    } catch (_) {
      autoExplainToggle.disabled = true;
      autoExplainToggle.textContent = 'Unavailable';
    }
  }

  autoExplainToggle.addEventListener('click', async () => {
    autoExplainToggle.disabled = true;
    const enabled = autoExplainToggle.getAttribute('aria-pressed') !== 'true';
    try {
      const response = await fetch('/api/alerts/settings', {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({critical_alert_auto_explain: enabled})});
      if (!response.ok) throw new Error('settings update failed');
      renderAutoExplain(Boolean((await response.json()).critical_alert_auto_explain));
    } catch (_) {
      autoExplainToggle.textContent = 'Update failed';
      setTimeout(loadAutoExplainSetting, 1500);
    }
  });

  async function load(loadMore = false) {
    if (loadMore && busy) return;
    const generation = ++loadGeneration;
    busy = true;
    if (!loadMore) {
      nextCursor = null;
      renderedItems = [];
    }
    const query = new URLSearchParams({limit: '100'});
    // The visible list is client-filtered by time; continue from the number
    // of raw items already fetched so the next page cannot reuse a stale or
    // malformed cursor after a live refresh.
    if (loadMore) query.set('offset', String(renderedItems.length));
    try {
      const response = await fetch(`/api/alerts?${query}`, {cache: 'no-store'});
      if (!response.ok) throw new Error('load failed');
      const data = await response.json();
      if (generation !== loadGeneration) return;
      const incoming = data.items || [];
      const seen = new Set(renderedItems.map(item => String(item.id)));
      const merged = loadMore ? renderedItems.concat(incoming.filter(item => !seen.has(String(item.id)))) : incoming;
      nextCursor = data.next_cursor || null;
      renderItems(merged);
      loadMoreButton.hidden = !nextCursor;
      state.textContent = `${data.total || 0} alert event${data.total === 1 ? '' : 's'} · updated just now`;
    } catch (_) {
      if (generation !== loadGeneration) return;
      list.innerHTML = '<div class="state"><strong>Alerts unavailable</strong>PostgreSQL did not return the alert read model.</div>';
      state.textContent = 'Unable to load alerts';
    } finally {
      if (generation === loadGeneration) busy = false;
    }
  }

  status.addEventListener('change', () => load(false));
  timeFilter.querySelectorAll('[data-range]').forEach(button => button.addEventListener('click', () => {
    selectedRange = button.dataset.range;
    customStart = ''; customEnd = '';
    document.getElementById('alert-time-trigger').textContent = button.textContent.trim() + ' ⌄';
    timeFilter.querySelectorAll('[data-range]').forEach(option => option.classList.toggle('active', option === button));
    document.getElementById('alert-time-popover').hidden = true;
    document.getElementById('alert-time-trigger').setAttribute('aria-expanded', 'false');
    render(renderedItems);
  }));
  document.getElementById('alert-time-trigger').addEventListener('click', () => { const popover = document.getElementById('alert-time-popover'); popover.hidden = !popover.hidden; document.getElementById('alert-time-trigger').setAttribute('aria-expanded', String(!popover.hidden)); });
  document.getElementById('alert-time-apply').addEventListener('click', () => { const start = document.getElementById('alert-time-start').value; const end = document.getElementById('alert-time-end').value; if (start || end) { customStart = start; customEnd = end; selectedRange = ''; document.getElementById('alert-time-trigger').textContent = 'Custom range ⌄'; } else { customStart = ''; customEnd = ''; const active = timeFilter.querySelector('[data-range].active'); document.getElementById('alert-time-trigger').textContent = `${active?.textContent.trim() || 'Last 24 hours'} ⌄`; } document.getElementById('alert-time-popover').hidden = true; document.getElementById('alert-time-trigger').setAttribute('aria-expanded', 'false'); render(renderedItems); });
  loadMoreButton.addEventListener('click', () => load(true));
  setInterval(() => { if (!document.hidden) load(); }, 5000);
  loadAutoExplainSetting();
  load();
})();
