// Smoke test: 5 VUs, 30s — basic health validation under light load.
// Run: k6 run k6/smoke.js --env BASE_URL=http://localhost:8080 --env TOKEN=<jwt>

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, thresholds } from './config.js';

export const options = {
  vus: 5,
  duration: '30s',
  thresholds,
};

const headers = { Authorization: `Bearer ${__ENV.TOKEN || ''}` };

export default function () {
  const health = http.get(`${BASE_URL}/health`);
  check(health, { 'health 200': (r) => r.status === 200 });

  const ready = http.get(`${BASE_URL}/ready`);
  check(ready, { 'ready 200': (r) => r.status === 200 });

  const findings = http.get(`${BASE_URL}/api/v1/findings`, { headers });
  check(findings, { 'findings 2xx': (r) => r.status >= 200 && r.status < 300 });

  const compliance = http.get(`${BASE_URL}/api/v1/compliance/frameworks`, { headers });
  check(compliance, { 'compliance 2xx': (r) => r.status >= 200 && r.status < 300 });

  sleep(1);
}
