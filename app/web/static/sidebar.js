(function () {
  const STORAGE_KEY = 'sentinel-sidebar-collapsed';
  const shell = document.querySelector('.shell');
  const aside = shell?.querySelector(':scope > aside[data-sidebar]');
  if (!shell || !aside) return;

  const page = aside.dataset.page || '';
  const items = [
    { key: 'overview', href: '/', icon: '⌁', label: 'Overview', view: 'overview' },
    { key: 'ip-intelligence', href: '/#threats', icon: '◎', label: 'IP Intelligence', view: 'threats' },
    { key: 'alerts', href: '/alerts', icon: '!', label: 'Alerts' },
    { key: 'raw-logs', href: '/raw-logs', icon: '≋', label: 'Raw Log Tail' },
  ];
  const activeKey = page === 'dashboard'
    ? (location.hash === '#threats' ? 'ip-intelligence' : 'overview')
    : page === 'region-detail' ? '' : page;
  aside.innerHTML = `<div class="brand"><div class="brand-mark">S</div><div><strong>Sentinel Hub</strong><small>remote monitor</small></div></div><nav aria-label="Main navigation">${items.map(item => `<a class="nav-item${item.key === activeKey ? ' active' : ''}" data-view="${item.view || ''}" href="${item.href}"${item.key === activeKey ? ' aria-current="page"' : ''}><span class="nav-icon">${item.icon}</span>${item.label}</a>`).join('')}</nav>${page === 'dashboard' ? `<div class="sidebar-health" id="health-widget" role="button" tabindex="0" title="Click to view infrastructure health diagnostics"><div class="health-head"><div class="eyebrow">System Status</div><div class="online"><span class="dot" id="collector-dot"></span><span id="collector-state">Checking…</span></div></div><div class="health-grid"><div class="health-chip" id="chip-pg"><span class="dot-sm"></span>PG</div><div class="health-chip" id="chip-ch"><span class="dot-sm"></span>CH</div><div class="health-chip" id="chip-rules"><span class="dot-sm"></span>Rules</div><div class="health-chip" id="chip-stream"><span class="dot-sm"></span>Stream</div></div></div>` : ''}`;

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'sidebar-toggle';
  button.textContent = '‹';
  button.setAttribute('aria-controls', aside.id || 'main-navigation');
  aside.id = aside.id || 'main-navigation';
  const brand = aside.querySelector('.brand');
  aside.insertBefore(button, brand || aside.firstChild);

  const setCollapsed = (collapsed) => {
    shell.classList.toggle('sidebar-collapsed', collapsed);
    button.setAttribute('aria-expanded', String(!collapsed));
    button.setAttribute('aria-label', collapsed ? 'Mở rộng menu' : 'Thu gọn menu');
    button.textContent = collapsed ? '›' : '‹';
    localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0');
  };

  const saved = localStorage.getItem(STORAGE_KEY) === '1';
  setCollapsed(saved);
  button.addEventListener('click', () => setCollapsed(!shell.classList.contains('sidebar-collapsed')));
})();
