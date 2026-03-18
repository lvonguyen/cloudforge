// Stress test: ramp 0 -> 50 -> 0 VUs over 3 minutes.
// Exercises findings, attack paths, and compliance under sustained load.
// Run: k6 run k6/stress.js --env BASE_URL=http://localhost:8080 --env TOKEN=<jwt>

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BASE_URL, thresholds } from './config.js';

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '1m', target: 50 },
    { duration: '30s', target: 50 },
    { duration: '1m', target: 0 },
  ],
  thresholds,
};

const headers = { Authorization: `Bearer ${__ENV.TOKEN || ''}` };

export default function () {
  const findings = http.get(`${BASE_URL}/api/v1/findings`, { headers });
  check(findings, {
    'findings 2xx': (r) => r.status >= 200 && r.status < 300,
    'findings < 2s': (r) => r.timings.duration < 2000,
  });

  const paths = http.get(`${BASE_URL}/api/v1/attack-paths?page=1&per_page=20`, { headers });
  check(paths, { 'paths 2xx': (r) => r.status >= 200 && r.status < 300 });

  const compliance = http.get(`${BASE_URL}/api/v1/compliance/frameworks`, { headers });
  check(compliance, { 'compliance 2xx': (r) => r.status >= 200 && r.status < 300 });

  const agents = http.get(`${BASE_URL}/api/v1/agents`, { headers });
  check(agents, { 'agents 2xx': (r) => r.status >= 200 && r.status < 300 });

  sleep(0.5);
}
