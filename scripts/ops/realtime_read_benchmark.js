import http from 'k6/http';
import { check } from 'k6';

const base = (__ENV.BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const mode = __ENV.MODE || 'all';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '30s',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1000', 'p(99)<2000'],
  },
};

export default function () {
  const requests = {
    health: ['GET', `${base}/health`, null, { tags: { endpoint: 'health' } }],
    summary: ['GET', `${base}/api/ips/summary?start=2026-09-14T00:00:00Z&end=2026-09-15T00:00:00Z`, null, { tags: { endpoint: 'summary' } }],
    updates: ['GET', `${base}/api/ips/updates?after=0&limit=50`, null, { tags: { endpoint: 'updates' } }],
  };
  const selected = mode === 'all' ? Object.values(requests) : [requests[mode]];
  const responses = http.batch(selected);

  responses.forEach((response) => check(response, { [`${mode} is 200`]: (item) => item.status === 200 }));
}
