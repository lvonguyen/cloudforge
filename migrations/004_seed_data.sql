-- migrations/004_seed_data.sql
-- Seed data for CloudForge local development
-- Populates tables from migrations 002 and 003 with demo data matching frontend mock JSON
-- Run: psql -d cloudforge -f migrations/004_seed_data.sql

-- ============================================================
-- Users (18 rows — 6 admin, 6 operator, 6 requester)
-- ============================================================
INSERT INTO users (id, email, name, role, department, team, last_login, status) VALUES
  ('u-001', 'admin1@contoso.dev', 'Sarah Chen', 'admin', 'Engineering', 'Platform Security', '2026-02-26 09:14:00+00', 'active'),
  ('u-002', 'operator1@contoso.dev', 'Marcus Rivera', 'operator', 'Operations', 'Cloud Ops', '2026-02-26 08:52:00+00', 'active'),
  ('u-003', 'operator2@contoso.dev', 'Priya Patel', 'operator', 'Operations', 'Cloud Ops', '2026-02-25 17:30:00+00', 'active'),
  ('u-004', 'user1@contoso.dev', 'James Okafor', 'requester', 'Engineering', 'Data Platform', '2026-02-24 14:05:00+00', 'active'),
  ('u-005', 'user2@contoso.dev', 'Elena Vasquez', 'requester', 'Engineering', 'Payments', '2026-02-20 11:42:00+00', 'inactive'),
  ('u-006', 'admin2@contoso.dev', 'David Kim', 'admin', 'Engineering', 'Platform Security', '2026-02-26 07:30:00+00', 'active'),
  ('u-007', 'admin3@contoso.dev', 'Fatima Al-Hassan', 'admin', 'Security', 'Compliance', '2026-02-25 16:20:00+00', 'active'),
  ('u-008', 'admin4@contoso.dev', 'Thomas Berg', 'admin', 'Engineering', 'Auth', '2026-02-24 09:15:00+00', 'active'),
  ('u-009', 'admin5@contoso.dev', 'Yuki Tanaka', 'admin', 'Operations', 'FinOps', '2026-02-22 13:45:00+00', 'active'),
  ('u-010', 'admin6@contoso.dev', 'Robert Nguyen', 'admin', 'Engineering', 'ML Platform', '2026-02-18 10:00:00+00', 'inactive'),
  ('u-011', 'operator3@contoso.dev', 'Aisha Johnson', 'operator', 'Operations', 'Cloud Ops', '2026-02-26 06:00:00+00', 'active'),
  ('u-012', 'operator4@contoso.dev', 'Carlos Mendez', 'operator', 'Operations', 'Cloud Ops', '2026-02-25 14:22:00+00', 'active'),
  ('u-013', 'operator5@contoso.dev', 'Sophie Müller', 'operator', 'Security', 'Compliance', '2026-02-23 11:30:00+00', 'active'),
  ('u-014', 'operator6@contoso.dev', 'Raj Krishnan', 'operator', 'Operations', 'FinOps', '2026-02-15 08:00:00+00', 'inactive'),
  ('u-015', 'user3@contoso.dev', 'Emily Sato', 'requester', 'Engineering', 'Catalog', '2026-02-26 08:10:00+00', 'active'),
  ('u-016', 'user4@contoso.dev', 'Omar Hassan', 'requester', 'Engineering', 'Payments', '2026-02-25 15:45:00+00', 'active'),
  ('u-017', 'user5@contoso.dev', 'Anna Kowalski', 'requester', 'Engineering', 'Auth', '2026-02-24 10:30:00+00', 'active'),
  ('u-018', 'user6@contoso.dev', 'Wei Zhang', 'requester', 'Data Science', 'ML Platform', '2026-02-22 09:20:00+00', 'active')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Compliance frameworks (6 rows — matching frameworks.json)
-- ============================================================
INSERT INTO compliance_frameworks (id, name, description, version, category, total_controls, controls_passing, controls_failing, score, relevant_for, last_assessed_at) VALUES
  ('nist-csf', 'NIST CSF 2.0', 'NIST Cybersecurity Framework v2.0', '2.0', 'security', 108, 87, 21, 80.6, ARRAY['aws','azure','gcp'], '2026-02-27 08:00:00+00'),
  ('pci-dss', 'PCI-DSS v4.0', 'Payment Card Industry Data Security Standard v4.0', '4.0', 'compliance', 64, 52, 12, 81.3, ARRAY['aws','azure'], '2026-02-27 08:00:00+00'),
  ('hipaa', 'HIPAA', 'Health Insurance Portability and Accountability Act', '2024', 'compliance', 42, 38, 4, 90.5, ARRAY['aws'], '2026-02-27 08:00:00+00'),
  ('iso-27001', 'ISO 27001:2022', 'International standard for ISMS', '2022', 'security', 93, 71, 22, 76.3, ARRAY['aws','azure','gcp'], '2026-02-27 08:00:00+00'),
  ('iso-42001', 'ISO 42001:2023', 'AI Management System standard', '2023', 'ai-governance', 38, 21, 17, 55.3, ARRAY['aws','azure','gcp'], '2026-02-27 08:00:00+00'),
  ('tisax', 'TISAX', 'Trusted Information Security Assessment Exchange', '6.0', 'automotive', 56, 44, 12, 78.6, ARRAY['azure'], '2026-02-27 08:00:00+00')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- AI agents (4 core agents — matching first 4 from agents.json)
-- ============================================================
INSERT INTO ai_agents (id, name, description, framework, version, owner, team, environment, risk_level, status, last_active_at, total_invocations, avg_latency_ms, error_rate) VALUES
  ('550e8400-e29b-41d4-a716-446655440001', 'CloudAudit Agent', 'Autonomous agent for continuous cloud configuration auditing', 'langchain', '2.1.0', 'admin1@contoso.dev', 'security-platform', 'prod', 'low', 'active', '2026-02-27 08:30:00+00', 12847, 102340, 0.0012),
  ('550e8400-e29b-41d4-a716-446655440002', 'RemediationBot', 'Automated remediation agent with dry-run validation and rollback', 'autogen', '1.4.2', 'ops-team@contoso.dev', 'cloud-ops', 'prod', 'high', 'active', '2026-02-27 09:15:00+00', 3421, 47230, 0.0340),
  ('550e8400-e29b-41d4-a716-446655440003', 'ThreatIntelAgent', 'Threat intelligence correlation agent using CrewAI', 'crewai', '0.8.1', 'security@contoso.dev', 'threat-intel', 'staging', 'medium', 'suspended', '2026-02-24 12:00:00+00', 891, 85000, 0.0500),
  ('550e8400-e29b-41d4-a716-446655440004', 'CostOptimizer', 'FinOps optimization agent using stateful workflow', 'langgraph', '0.2.5', 'finops@contoso.dev', 'finops', 'prod', 'low', 'active', '2026-02-27 06:00:00+00', 5632, 120000, 0.0080)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Sample findings (first 8 — matching original findings.json)
-- Full 80 findings can be loaded via: node scripts/generate-findings.mjs | psql -c "COPY ..."
-- ============================================================
INSERT INTO findings (id, source, type, title, cloud_provider, region, account_id, account_name, environment_type, severity, static_severity, ai_risk_score, ai_risk_level, status, workflow_status, category, auto_remediatable, first_found_at, due_date) VALUES
  ('f-001', 'aws-security-hub', 'vulnerability', 'Critical CVE-2024-9999 in EC2 instance payments/ec2-i-abc123', 'aws', 'ap-southeast-3', '123456789012', 'acme-payments-prod', 'production', 'CRITICAL', 'CRITICAL', 9.8, 'critical', 'open', 'triaged', 'VULNERABILITY', false, '2026-02-25 10:00:00+00', '2026-02-26 10:00:00+00'),
  ('f-002', 'aws-security-hub', 'publicly_accessible', 'S3 bucket catalog-assets is publicly accessible', 'aws', 'us-east-1', '123456789012', 'acme-catalog-prod', 'production', 'HIGH', 'HIGH', 7.2, 'high', 'open', 'new', 'MISCONFIGURATION', true, '2026-02-24 14:00:00+00', '2026-03-06 14:00:00+00'),
  ('f-003', 'azure-defender', 'misconfiguration', 'Azure VM disk encryption disabled on qa-vm-westus2-01', 'azure', 'westus2', 'sub-acme-qa', 'Acme Corp QA Subscription', 'qa', 'HIGH', 'HIGH', 6.1, 'high', 'open', 'new', 'MISCONFIGURATION', true, '2026-02-20 09:00:00+00', '2026-03-20 09:00:00+00'),
  ('f-004', 'gcp-scc', 'logging_disabled', 'Cloud Audit Logging disabled for auth-svc GKE cluster', 'gcp', 'us-central1', 'acme-auth-prod', 'Acme Corp Auth Production', 'production', 'MEDIUM', 'MEDIUM', 5.4, 'medium', 'open', 'in_progress', 'COMPLIANCE', true, '2026-02-18 11:00:00+00', '2026-03-18 11:00:00+00'),
  ('f-005', 'aws-security-hub', 'iam_anomaly', 'IAM role with wildcard * permission in payments account', 'aws', 'us-east-1', '123456789012', 'acme-payments-prod', 'production', 'HIGH', 'HIGH', 7.8, 'high', 'open', 'assigned', 'IDENTITY', false, '2026-02-22 16:00:00+00', '2026-03-01 16:00:00+00'),
  ('f-006', 'gcp-scc', 'encryption_missing', 'GKE persistent volume unencrypted — catalog/pvc-data-01', 'gcp', 'us-central1', 'acme-catalog-prod', 'Acme Corp Catalog Production', 'production', 'MEDIUM', 'MEDIUM', 4.8, 'medium', 'open', 'new', 'MISCONFIGURATION', false, '2026-02-15 10:00:00+00', '2026-03-15 10:00:00+00'),
  ('f-007', 'azure-defender', 'misconfiguration', 'NSG allows unrestricted inbound SSH (port 22)', 'azure', 'eastus', 'sub-acme-dev', 'Acme Corp Dev Subscription', 'development', 'MEDIUM', 'MEDIUM', 4.2, 'medium', 'open', 'new', 'NETWORK', true, '2026-02-10 08:00:00+00', '2026-03-10 08:00:00+00'),
  ('f-008', 'aws-security-hub', 'insecure_configuration', 'RDS instance db-payments-01 has public accessibility enabled', 'aws', 'us-east-1', '123456789012', 'acme-payments-prod', 'production', 'CRITICAL', 'CRITICAL', 9.1, 'critical', 'open', 'assigned', 'MISCONFIGURATION', true, '2026-02-26 07:00:00+00', '2026-02-27 07:00:00+00')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Sample audit log entries (first 7 — matching AuditLog.tsx)
-- ============================================================
INSERT INTO audit_log (id, action, actor_email, actor_role, target_type, target_id, result, ip_address, timestamp) VALUES
  ('evt-001', 'exception.approve', 'admin1@contoso.dev', 'admin', 'exception', 'EXC-003', 'success', '10.0.1.5', '2026-02-26 09:14:32+00'),
  ('evt-002', 'finding.remediate', 'operator1@contoso.dev', 'operator', 'finding', 'f-002', 'success', '10.0.2.12', '2026-02-26 09:01:10+00'),
  ('evt-003', 'policy.evaluate', 'operator2@contoso.dev', 'operator', 'policy', 'pol-001', 'denied', '10.0.2.8', '2026-02-26 08:55:44+00'),
  ('evt-004', 'exception.create', 'user1@contoso.dev', 'requester', 'exception', 'EXC-004', 'success', '10.0.3.44', '2026-02-26 08:44:20+00'),
  ('evt-005', 'agent.start', 'system@contoso.dev', 'admin', 'agent', 'CloudAudit Agent', 'success', '127.0.0.1', '2026-02-26 08:30:01+00'),
  ('evt-006', 'scan.complete', 'system@contoso.dev', 'admin', 'scan', 'aws-prod-account', 'success', '127.0.0.1', '2026-02-25 22:10:05+00'),
  ('evt-007', 'finding.suppress', 'operator2@contoso.dev', 'operator', 'finding', 'f-007', 'error', '10.0.2.8', '2026-02-25 17:30:15+00')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Sample remediations (first 5 — mixed tiers and statuses)
-- ============================================================
INSERT INTO remediations (id, finding_id, domain, handler, tier, status, executor_email) VALUES
  ('rem-001', 'f-002', 'storage', 's3-acl-remediator', 1, 'completed', 'system@contoso.dev'),
  ('rem-002', 'f-003', 'compute', 'vm-disk-encrypt', 2, 'in_progress', 'operator1@contoso.dev'),
  ('rem-003', 'f-007', 'network', 'nsg-rule-remediator', 1, 'completed', 'system@contoso.dev'),
  ('rem-004', 'f-008', 'database', 'rds-access-remediator', 2, 'pending', NULL),
  ('rem-005', 'f-005', 'identity', 'manual-escalation', 3, 'pending', NULL)
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Sample cost summaries (monthly aggregates)
-- ============================================================
INSERT INTO cost_summaries (period_start, period_end, cloud_provider, account_id, service, amount) VALUES
  ('2026-02-01', '2026-02-28', 'aws', '123456789012', 'EC2', 728000.00),
  ('2026-02-01', '2026-02-28', 'aws', '123456789012', 'RDS', 273000.00),
  ('2026-02-01', '2026-02-28', 'aws', '123456789012', 'S3', 182000.00),
  ('2026-02-01', '2026-02-28', 'aws', '123456789012', 'Lambda', 145600.00),
  ('2026-02-01', '2026-02-28', 'aws', '123456789012', 'EKS', 218400.00),
  ('2026-02-01', '2026-02-28', 'azure', 'sub-shared-001', 'Virtual Machines', 245000.00),
  ('2026-02-01', '2026-02-28', 'azure', 'sub-shared-001', 'AKS', 140000.00),
  ('2026-02-01', '2026-02-28', 'azure', 'sub-shared-001', 'Storage', 105000.00),
  ('2026-02-01', '2026-02-28', 'gcp', 'proj-analytics-001', 'BigQuery', 126000.00),
  ('2026-02-01', '2026-02-28', 'gcp', 'proj-gke-001', 'GKE', 70000.00)
ON CONFLICT DO NOTHING;
