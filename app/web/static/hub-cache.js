(() => {
  const VERSION = 'hub:v2:';
  const CACHE_PATHS = [
    '/api/ips?limit=500',
    '/api/regions?limit=200',
    '/api/regions/demand-signal?limit=24',
    '/api/analytics/traffic',
  ];

  function keyFor(url) {
    const parsed = new URL(url, window.location.origin);
    return VERSION + parsed.pathname + parsed.search;
  }

  async function cachedFetch(url, ttlMs) {
    const key = keyFor(url);
    try {
      const raw = sessionStorage.getItem(key);
      if (raw) {
        const cached = JSON.parse(raw);
        if (cached && Date.now() - cached.ts < ttlMs) return cached.data;
        sessionStorage.removeItem(key);
      }
    } catch (_) {
      try { sessionStorage.removeItem(key); } catch (_) {}
    }

    const response = await fetch(url, {cache: 'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    try {
      sessionStorage.setItem(key, JSON.stringify({ts: Date.now(), data}));
    } catch (_) {
      // Quota or private-mode storage failure: network result remains usable.
    }
    return data;
  }

  function invalidateHubCache() {
    try {
      for (const path of CACHE_PATHS) sessionStorage.removeItem(VERSION + path);
      for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
        const key = sessionStorage.key(index);
        if (key && key.startsWith(VERSION)) sessionStorage.removeItem(key);
      }
    } catch (_) {}
  }

  window.cachedFetch = cachedFetch;
  window.invalidateHubCache = invalidateHubCache;
})();
