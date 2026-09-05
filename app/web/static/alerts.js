(() => {
  const list = document.getElementById('alerts-list');
  const state = document.getElementById('alerts-state');
  const severity = document.getElementById('alert-severity');
  const status = document.getElementById('alert-status');
  const autoExplainToggle = document.getElementById('auto-explain-toggle');
  let busy = false;

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

  function render(items) {
    if (!items.length) {
      list.innerHTML = '<div class="state"><strong>No alerts match these filters.</strong>New meaningful severity changes will appear here.</div>';
      return;
    }
    list.innerHTML = items.map(item => `
      <article class="alert-card ${esc(item.severity)} ${esc(item.status)}" data-alert-id="${esc(item.id)}">
        <div class="alert-card-head">
          <div class="alert-severity"><span class="alert-dot"></span><strong>${esc(label(item.severity))}</strong><span class="alert-status">${esc(label(item.status))}</span></div>
          <time datetime="${esc(item.created_at || '')}">${esc(when(item.created_at))}</time>
        </div>
        <div class="alert-card-body">
          <div><h3>${esc(item.title)}</h3><p>${esc(item.description)}</p><div class="alert-meta"><span>Reason: ${esc(item.reason_type)}</span><span>IP: <a href="/ip/${encodeURIComponent(item.ip)}?mode=live">${esc(item.ip)}</a></span></div></div>
          <div class="alert-actions">
            <a class="secondary alert-open" href="/ip/${encodeURIComponent(item.ip)}?mode=live">Open IP</a>
            ${item.status === 'new' ? '<button class="secondary" data-status="acknowledged">Acknowledge</button>' : ''}
            ${item.status !== 'resolved' ? '<button class="secondary" data-status="resolved">Resolve</button>' : ''}
          </div>
        </div>
      </article>`).join('');
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

  async function load() {
    if (busy) return;
    busy = true;
    const query = new URLSearchParams({limit: '100'});
    if (severity.value) query.set('severity', severity.value);
    if (status.value) query.set('status', status.value);
    try {
      const response = await fetch(`/api/alerts?${query}`, {cache: 'no-store'});
      if (!response.ok) throw new Error('load failed');
      const data = await response.json();
      render(data.items || []);
      state.textContent = `${data.total || 0} alert${data.total === 1 ? '' : 's'} · updated just now`;
    } catch (_) {
      list.innerHTML = '<div class="state"><strong>Alerts unavailable</strong>PostgreSQL did not return the alert read model.</div>';
      state.textContent = 'Unable to load alerts';
    } finally { busy = false; }
  }

  severity.addEventListener('change', load);
  status.addEventListener('change', load);
  setInterval(() => { if (!document.hidden) load(); }, 5000);
  loadAutoExplainSetting();
  load();
})();
