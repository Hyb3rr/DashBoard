"""Behavioral race tests for dashboard analytics using delayed fetch responses."""

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).parents[1]


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JavaScript behavior tests")
def test_latest_dashboard_analytics_query_wins_and_keeps_filter_identity():
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const slice = (start, end) => {
  const a = source.indexOf(start), b = source.indexOf(end, a);
  assert(a >= 0 && b > a, `missing source section ${start}`);
  return source.slice(a, b).trim();
};
const state = slice("const TRAFFIC_WINDOW_KEY=", "function syncTimePickerUi(");
const applyFilter = slice("function applyTrafficFilter(", "function clearTrafficFilter(");
const clearFilter = slice("function clearTrafficFilter(", "function setClassificationTrafficFilter(");
const setClassificationFilter = slice("function setClassificationTrafficFilter(", "function renderTraffic(");
const loadTraffic = slice("async function loadTraffic(){", "let countryDemandPeriod=");
const loadSummary = slice("async function loadIpSummary(", "function recordRealtimeLatency(");

function makeHarness(savedState = null) {
  const requests = [], rendered = [], summaryRenders = [], analyticsRenders = [],
    classification = { value: '' }, elements = { 'traffic-chart': { innerHTML: '' } };
  const sandbox = {
    requests, rendered, summaryRenders, analyticsRenders, classification, elements,
    savedState,
    sessionStorage: {
      getItem() { return sandbox.savedState; },
      setItem(_key, value) { sandbox.savedState = value; },
    },
    document: { querySelectorAll() { return []; } },
    URLSearchParams,
    fetch(url) { return new Promise(resolve => requests.push({ url, resolve })); },
    apiUrl(path) { return path; },
    syncTrafficInputs() {},
    renderTraffic(data) {
      rendered.push({ marker: data.marker, start: data.start, end: data.end, filter: data.filter,
        topIps: (data.top_ips || []).map(row => row.ip), topPaths: (data.top_paths || []).map(row => row.path) });
    },
    renderAnalytics() {},
    summary() {},
    loadIpSnapshot() {},
    notify() {},
    esc(value) { return String(value); },
    setTimeout, clearTimeout,
    console,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(`
    let ipSummary=null,ipsReady=true,ipPage=1;
    const $=id=>id==='classification'?classification:elements[id]||{value:'',innerHTML:''};
    function renderAnalytics(){analyticsRenders.push({
      donutIdentity: trafficClassificationSummary?.queryIdentity || null,
      currentIdentity: trafficQueryIdentity(snapshotTrafficQuery()),
      summary: trafficClassificationSummary || null,
    })}
    function summary(){summaryRenders.push(ipSummary?.marker||null)}
    function captureTrafficPromises(){const actual=loadTraffic;loadTraffic=function(){const promise=actual();globalThis.capturedPromises.push(promise);return promise}}
        ${state}
        ${applyFilter}
        ${clearFilter}
        ${setClassificationFilter}
            ${loadTraffic}
    ${loadSummary}
  `, context);
  context.realLoadIpSummary = context.loadIpSummary;
  context.loadIpSummary = async () => true;
  return { context, requests, rendered, summaryRenders, analyticsRenders };
}

function response(resolve, marker, filter, window = {}, classificationSummary = null) {
  resolve({
    ok: true,
    async json() {
      return {
        marker, start: window.start || '2026-09-26T10:00:00Z', end: window.end || '2026-09-26T11:00:00Z',
        top_ips: [{ ip: `${marker}-ip` }], top_paths: [{ path: `${marker}-path` }],
        filter, classification_summary: classificationSummary || {
          total_ips: marker === 'empty' ? 0 : 1,
          classification: { critical: marker === 'critical' ? 1 : 0, medium: 0, low: 0, good: 0, unknown: marker === 'critical' ? 0 : (marker === 'empty' ? 0 : 1) },
        },
      };
    },
  });
}
const parsed = url => new URL(url, 'http://hub.test');

(async () => {
  // A starts first; B completes first. Only B may mutate the analytics UI.
  {
    const h = makeHarness();
    vm.runInContext("trafficFilterType='ip';trafficFilterValue='203.0.113.1'", h.context);
    const a = h.context.loadTraffic();
    vm.runInContext("trafficFilterValue='203.0.113.2'", h.context);
    const b = h.context.loadTraffic();
    assert.equal(h.requests.length, 2, 'new query must not reuse an in-flight request');
    response(h.requests[1].resolve, 'B', { type: 'ip', value: '203.0.113.2', exclude: false });
    await b;
    response(h.requests[0].resolve, 'A', { type: 'ip', value: '203.0.113.1', exclude: false });
    await a;
    assert.deepEqual(h.rendered.map(row => row.marker), ['B']);
    assert.deepEqual(h.rendered[0].filter, { type: 'ip', value: '203.0.113.2', exclude: false });
    assert.deepEqual(h.rendered[0].topIps, ['B-ip']);
    assert.deepEqual(h.rendered[0].topPaths, ['B-path']);
    assert.equal(h.analyticsRenders[0].donutIdentity, h.analyticsRenders[0].currentIdentity);
  }

  // A stale traffic response cannot replace the current donut data or its query identity.
  {
    const h = makeHarness();
    vm.runInContext("trafficFilterType='classification';trafficFilterValue='critical'", h.context);
    const a = h.context.loadTraffic();
    const aIdentity = vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context);
    vm.runInContext("trafficFilterValue='medium'", h.context);
    const b = h.context.loadTraffic();
    const bIdentity = vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context);
    response(h.requests[1].resolve, 'summary-B', { type: 'classification', value: 'medium', exclude: false }, {}, {
      total_ips: 2, classification: { critical: 0, medium: 2, low: 0, good: 0, unknown: 0 },
    });
    await b;
    response(h.requests[0].resolve, 'summary-A', { type: 'classification', value: 'critical', exclude: false }, {}, {
      total_ips: 3, classification: { critical: 3, medium: 0, low: 0, good: 0, unknown: 0 },
    });
    await a;
    const donutState = JSON.parse(vm.runInContext('JSON.stringify(trafficClassificationSummary)', h.context));
    assert.notEqual(aIdentity, bIdentity);
    assert.equal(donutState.queryIdentity, bIdentity);
    assert.equal(donutState.total_ips, 2);
    assert.deepEqual(donutState.classification, { critical: 0, medium: 2, low: 0, good: 0, unknown: 0 });
    assert.equal(h.analyticsRenders.length, 1, 'the stale response never triggers analytics rendering');
    assert.equal(h.analyticsRenders[0].donutIdentity, bIdentity);
  }

  // A time-window switch is also latest-query-wins, including the donut summary.
  {
    const h = makeHarness();
    vm.runInContext("trafficRange='1h';trafficStart='2026-09-25 10:00';trafficEnd='2026-09-25 11:00'", h.context);
    const a = h.context.loadTraffic();
    vm.runInContext("trafficStart='2026-09-26 10:00';trafficEnd='2026-09-26 11:00'", h.context);
    const b = h.context.loadTraffic();
    assert.equal(h.requests.length, 2);
    assert.equal(parsed(h.requests[0].url).searchParams.get('start'), new Date('2026-09-25T10:00').toISOString());
    assert.equal(parsed(h.requests[1].url).searchParams.get('start'), new Date('2026-09-26T10:00').toISOString());
    const windowStart = new Date('2026-09-26T10:00').toISOString();
    const windowEnd = new Date('2026-09-26T11:00').toISOString();
    response(h.requests[1].resolve, 'window-B', null, { start: windowStart, end: windowEnd }); await b;
    response(h.requests[0].resolve, 'window-A', null); await a;
    assert.deepEqual(h.rendered.map(row => row.marker), ['window-B']);
    assert.equal(h.rendered[0].start, windowStart);
    assert.equal(h.rendered[0].end, windowEnd);
    assert.equal(h.analyticsRenders[0].donutIdentity, h.analyticsRenders[0].currentIdentity);
  }

  // Include -> exclude for path and IP: late include cannot replace exclude.
  for (const [type, value] of [['path', '/foo?a=1&b=2'], ['ip', '2001:db8::8']]) {
    const h = makeHarness(), promises = [];
    h.context.capturedPromises = promises;
    vm.runInContext('captureTrafficPromises()', h.context);
    h.context.applyTrafficFilter(type, value, false);
    h.context.applyTrafficFilter(type, value, true);
    assert.equal(h.requests.length, 2);
    const exclude = { type, value, exclude: true }, include = { type, value, exclude: false };
    response(h.requests[1].resolve, 'exclude', exclude); await promises[1];
    response(h.requests[0].resolve, 'include', include); await promises[0];
    assert.deepEqual(h.rendered.map(row => row.marker), ['exclude']);
    const query = parsed(h.requests[1].url).searchParams;
    assert.equal(query.get('filter_value'), value);
    assert.equal(query.get('exclude'), 'true');
  }

  // Classification/IP/path are replacement filters; clearing after rapid changes wins.
  {
    const h = makeHarness(), promises = [];
    h.context.capturedPromises = promises;
    vm.runInContext('captureTrafficPromises()', h.context);
    vm.runInContext("trafficFilterType='classification';trafficFilterValue='critical';classification.value='critical'", h.context);
    h.context.applyTrafficFilter('ip', '198.51.100.4', false);
    assert.equal(h.context.classification.value, '', 'switching from classification clears the old control');
    h.context.applyTrafficFilter('path', '/a%2Fb', false);
    h.context.clearTrafficFilter();
    assert.equal(vm.runInContext('trafficFilterType', h.context), '');
    assert.equal(vm.runInContext('trafficFilterValue', h.context), '');
    assert.equal(vm.runInContext('trafficExclude', h.context), false);
    assert.equal(h.requests.length, 3);
    response(h.requests[2].resolve, 'clear', null); await promises[2];
    response(h.requests[0].resolve, 'old-ip', { type: 'ip', value: '198.51.100.4', exclude: false }); await promises[0];
    response(h.requests[1].resolve, 'old-path', { type: 'path', value: '/a%2Fb', exclude: false }); await promises[1];
    assert.deepEqual(h.rendered.map(row => row.marker), ['clear']);
  }

  // Every control transition replaces, rather than composes with, the prior filter.
  {
    const h = makeHarness();
    h.context.loadTraffic = async () => true;
    vm.runInContext("trafficFilterType='classification';trafficFilterValue='critical';classification.value='critical'", h.context);
    h.context.applyTrafficFilter('path', '/x', false);
    assert.equal(h.context.classification.value, '');
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'path', '/x', false]);
    h.context.applyTrafficFilter('ip', '203.0.113.7', true);
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'ip', '203.0.113.7', true]);
    h.context.applyTrafficFilter('path', '/y', false);
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'path', '/y', false]);
    h.context.applyTrafficFilter('ip', '203.0.113.8', false);
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'ip', '203.0.113.8', false]);
    h.context.applyTrafficFilter('path', '/z', false);
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'path', '/z', false]);
    h.context.classification.value = 'medium';
    h.context.setClassificationTrafficFilter('medium');
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'classification', 'medium', false]);
    h.context.applyTrafficFilter('path', '/after-classification', false);
    assert.deepEqual(JSON.parse(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context)), ['', '', '1d', 'path', '/after-classification', false]);
  }

  // Path strings round-trip through URLSearchParams without normalization.
  for (const value of ['/foo?a=1&b=2', '/a%2Fb', '/unicode/đường-dẫn']) {
    const h = makeHarness();
    vm.runInContext(`trafficFilterType='path';trafficFilterValue=${JSON.stringify(value)}`, h.context);
    const params = vm.runInContext('trafficQueryParams(snapshotTrafficQuery())', h.context);
    assert.equal(new URLSearchParams(params.toString()).get('filter_value'), value);
  }

  // Query identity is stable for equal Q and changes when any Q member changes.
  {
    const h = makeHarness();
    vm.runInContext("trafficRange='1h';trafficStart='2026-09-26 10:00';trafficEnd='2026-09-26 11:00';trafficFilterType='path';trafficFilterValue='/wp-login.php';trafficExclude=false", h.context);
    const original = vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context);
    assert.equal(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context), original);
    for (const [field, value] of [
      ['trafficStart', '2026-09-26 10:01'], ['trafficEnd', '2026-09-26 11:01'],
      ['trafficRange', '6h'], ['trafficFilterType', 'ip'], ['trafficFilterValue', '198.51.100.1'],
      ['trafficExclude', true],
    ]) {
      vm.runInContext(`trafficStart='2026-09-26 10:00';trafficEnd='2026-09-26 11:00';trafficRange='1h';trafficFilterType='path';trafficFilterValue='/wp-login.php';trafficExclude=false;${field}=${JSON.stringify(value)}`, h.context);
      assert.notEqual(vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context), original, `${field} is part of Q`);
    }
    h.context.loadTraffic = async () => true;
    h.context.clearTrafficFilter();
    const cleared = vm.runInContext('snapshotTrafficQuery()', h.context);
    assert.deepEqual([cleared.filterType, cleared.filterValue, cleared.exclude], ['', '', false]);
  }

  // Restored custom window/filter are used for initial and realtime refreshes.
  {
    const restored = { range: '7d', start: '2026-09-20 10:00', end: '2026-09-21 10:00', filterType: 'path', filterValue: '/unicode/đường-dẫn', exclude: true };
    const h = makeHarness(JSON.stringify(restored));
    h.context.restoreTrafficWindow();
    const pending = h.context.loadTraffic();
    const first = parsed(h.requests[0].url);
    assert.equal(first.searchParams.get('range'), '7d');
    assert.equal(first.searchParams.get('start'), new Date(restored.start.replace(' ', 'T')).toISOString());
    assert.equal(first.searchParams.get('end'), new Date(restored.end.replace(' ', 'T')).toISOString());
    assert.equal(first.searchParams.get('filter_value'), restored.filterValue);
    assert.equal(first.searchParams.get('exclude'), 'true');
    // A scoped realtime refresh takes a fresh request from the current saved query.
    response(h.requests[0].resolve, 'initial', { type: 'path', value: restored.filterValue, exclude: true });
    await pending;
    const refreshed = h.context.loadTraffic();
    assert.equal(h.requests.length, 2);
    const second = parsed(h.requests[1].url);
    assert.equal(second.searchParams.get('start'), first.searchParams.get('start'));
    assert.equal(second.searchParams.get('end'), first.searchParams.get('end'));
    assert.equal(second.searchParams.get('filter_value'), restored.filterValue);
    response(h.requests[1].resolve, 'realtime', { type: 'path', value: restored.filterValue, exclude: true });
    await refreshed;
    assert.deepEqual(h.rendered.map(row => row.marker), ['initial', 'realtime']);
  }

  // A scoped summary request cannot overwrite a newer window/filter summary.
  {
    const h = makeHarness();
    h.context.loadIpSummary = h.context.realLoadIpSummary;
    vm.runInContext("trafficRange='1h';trafficFilterType='path';trafficFilterValue='/a';trafficRequestGeneration=1", h.context);
    const aIdentity = vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context);
    const a = h.context.loadIpSummary('2026-09-26T10:00:00Z', '2026-09-26T11:00:00Z', aIdentity, 1);
    vm.runInContext("trafficStart='2026-09-25 10:00';trafficEnd='2026-09-25 11:00';trafficRequestGeneration=2", h.context);
    const bIdentity = vm.runInContext('trafficQueryIdentity(snapshotTrafficQuery())', h.context);
    const b = h.context.loadIpSummary('2026-09-25T10:00:00Z', '2026-09-25T11:00:00Z', bIdentity, 2);
    assert.equal(h.requests.length, 2);
    h.requests[1].resolve({ ok: true, async json() { return { marker: 'B' }; } }); await b;
    h.requests[0].resolve({ ok: true, async json() { return { marker: 'A' }; } }); await a;
    assert.equal(vm.runInContext('ipSummary.marker', h.context), 'B');
    assert.deepEqual(h.summaryRenders, ['B']);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    script_path = ROOT / "app" / "web" / "static" / "dashboard.js"
    result = subprocess.run(
        [shutil.which("node"), "-e", script, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    javascript = script_path.read_text(encoding="utf-8")
    assert javascript.count("loadIpSummary(") == 2  # definition + scoped traffic caller only
    assert 'data-filter-value="${esc(value)}"' in javascript
    assert "action.dataset.filterValue" in javascript
    assert "params.set('filter_value',query.filterValue)" in javascript
