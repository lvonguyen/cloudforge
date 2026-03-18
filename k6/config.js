// Shared k6 configuration for CloudForge load tests.
// Usage: k6 run k6/smoke.js --env BASE_URL=http://localhost:8080 --env TOKEN=<jwt>

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export const thresholds = {
  http_req_duration: ['p(95)<500', 'p(99)<1500'],
  http_req_failed: ['rate<0.01'],
  http_reqs: ['rate>10'],
};
