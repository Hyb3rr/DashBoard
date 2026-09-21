/* Minimal first-party identity/event client. Disabled until the ingest endpoint ships. */
(function () {
  'use strict';
  const config = window.BEHAVIOR_TRACKING || {};
  const enabled = config.enabled === true;
  const endpoint = config.endpoint || '/api/behavior/events';
  const timeoutMs = Number(config.sessionTimeoutMs || 30 * 60 * 1000);
  const visitorKey = 'ipintel:visitor_id';
  const sessionKey = 'ipintel:session';
  const randomId = () => (window.crypto && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const readVisitor = () => {
    let value = window.localStorage.getItem(visitorKey);
    if (!value) { value = randomId(); window.localStorage.setItem(visitorKey, value); }
    return value;
  };
  const readSession = () => {
    const now = Date.now();
    let value;
    try { value = JSON.parse(window.sessionStorage.getItem(sessionKey) || 'null'); } catch (_) { value = null; }
    if (!value || !value.id || now - Number(value.lastSeen || 0) >= timeoutMs) value = { id: randomId(), lastSeen: now };
    else value.lastSeen = now;
    window.sessionStorage.setItem(sessionKey, JSON.stringify(value));
    return value.id;
  };
  const visitorId = readVisitor();
  const sessionId = readSession();
  const send = (eventName, fields = {}) => {
    if (!enabled) return false;
    const payload = { event_id: randomId(), timestamp: new Date().toISOString(), visitor_id: visitorId, session_id: sessionId, event_name: eventName, path: window.location.pathname, engagement_ms: null, key_event_name: null, ...fields };
    const body = JSON.stringify(payload);
    if (navigator.sendBeacon) return navigator.sendBeacon(endpoint, new Blob([body], { type: 'application/json' }));
    fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true }).catch(() => {});
    return true;
  };
  window.behaviorTracker = { visitorId, sessionId, send, pageView: () => send('page_view'), engagement: ms => send('engagement', { engagement_ms: ms }), keyEvent: name => send('key_event', { key_event_name: name }) };
  if (enabled) {
    window.addEventListener('load', () => send('page_view'), { once: true });
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') send('engagement', { engagement_ms: Math.max(0, Date.now() - (window.__behaviorStartedAt || Date.now())) }); });
  }
}());
