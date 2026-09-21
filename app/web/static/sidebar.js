(function () {
  const STORAGE_KEY = 'sentinel-sidebar-collapsed';
  const shell = document.querySelector('.shell');
  const aside = shell?.querySelector(':scope > aside');
  if (!shell || !aside) return;

  const style = document.createElement('style');
  style.textContent = `
    .shell.sidebar-collapsed { grid-template-columns: 64px minmax(0, 1fr); }
    .shell.sidebar-collapsed > aside { padding-inline: 10px; }
    .shell.sidebar-collapsed > aside .brand { display: none; }
    .shell.sidebar-collapsed > aside nav a { font-size: 0; }
    .shell.sidebar-collapsed > aside nav a > span { font-size: 16px; }
    .brand { position: relative; }
    .shell > aside { position: sticky; top: 0; height: 100vh; }
    .sidebar-toggle { position: absolute; top: 20px; right: 14px; z-index: 3; width: 32px; height: 32px; padding: 0; border: 1px solid var(--line, rgba(214,243,247,.1)); border-radius: 5px; background: transparent; color: var(--secondary, #9db2b7); cursor: pointer; font: 20px/1 ui-sans-serif,system-ui,sans-serif; }
    .sidebar-toggle:hover, .sidebar-toggle:focus-visible { background: var(--raised, #102229); color: var(--ink, #e6f1f2); }
    .shell.sidebar-collapsed .sidebar-toggle { position: static; display: block; margin: 0 auto; font-size: 20px; }
    .shell.sidebar-collapsed .sidebar-toggle::before { content: '›'; font-size: 20px; line-height: 1; }
  `;
  document.head.appendChild(style);

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
