#!/usr/bin/env node
/**
 * seed-postgres.mjs — Generate SQL seed file from aegis-seed output
 *
 * Reads testdata/seed/findings.json and generates a SQL file compatible with
 * the findings table (migration 002). Uses batched INSERT for fast loading.
 *
 * Usage:
 *   node scripts/seed-postgres.mjs --in testdata/seed/ --out testdata/seed/seed-findings.sql
 *   psql "$DATABASE_URL" < testdata/seed/seed-findings.sql
 *
 * Flags:
 *   --in DIR     Input directory (default: testdata/seed/)
 *   --out FILE   Output SQL file (default: testdata/seed/seed-findings.sql)
 *   --truncate   Add TRUNCATE before INSERT (default: true, use --no-truncate to skip)
 */

import { createReadStream, createWriteStream } from 'fs';
import { join, resolve } from 'path';

const args = process.argv.slice(2);
const getArg = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
const hasFlag = (name) => args.includes(name);

const IN_DIR = resolve(getArg('--in') ?? 'testdata/seed');
const OUT_FILE = resolve(getArg('--out') ?? join(IN_DIR, 'seed-findings.sql'));
const TRUNCATE = !hasFlag('--no-truncate');
const BATCH_SIZE = 100;

// Stream-parse a JSON array file, yielding one object at a time.
// Handles files exceeding V8 string limit (~512MB).
async function* streamJsonArray(filePath) {
  let buf = '';
  let depth = 0;
  let inStr = false;
  let esc = false;
  let objStart = -1;
  let scanPos = 0;
  let count = 0;

  for await (const chunk of createReadStream(filePath, { encoding: 'utf-8', highWaterMark: 256 * 1024 })) {
    buf += chunk;
    // Scan only newly appended data — state (depth/inStr/esc) carries over
    while (scanPos < buf.length) {
      const ch = buf[scanPos];
      if (esc) { esc = false; scanPos++; continue; }
      if (ch === '\\' && inStr) { esc = true; scanPos++; continue; }
      if (ch === '"') { inStr = !inStr; scanPos++; continue; }
      if (inStr) { scanPos++; continue; }
      if (ch === '{') { if (depth === 0) objStart = scanPos; depth++; }
      else if (ch === '}') {
        depth--;
        if (depth === 0 && objStart !== -1) {
          yield JSON.parse(buf.slice(objStart, scanPos + 1));
          count++;
          if (count % 50000 === 0) log(`  ...processed ${count} findings`);
          objStart = -1;
        }
      }
      scanPos++;
    }
    // Trim consumed content to prevent unbounded buffer growth
    const trimAt = objStart !== -1 ? objStart : scanPos;
    if (trimAt > 0) {
      buf = buf.slice(trimAt);
      scanPos -= trimAt;
      if (objStart !== -1) objStart = 0;
    }
  }
}

const log = (msg) => process.stderr.write(`[+] ${msg}\n`);

function esc(val) {
  if (val === null || val === undefined) return 'NULL';
  if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE';
  if (typeof val === 'number') return String(val);
  const s = String(val).replace(/'/g, "''");
  return `'${s}'`;
}

function escArray(arr) {
  if (!arr || arr.length === 0) return "'{}'";
  const items = arr.map(v => `"${String(v).replace(/"/g, '\\"')}"`).join(',');
  return `'{${items}}'`;
}

function escJsonb(val) {
  if (!val) return "'[]'::jsonb";
  return `'${JSON.stringify(val).replace(/'/g, "''")}'::jsonb`;
}

function escTimestamp(val) {
  if (!val) return 'NULL';
  return `'${val}'::timestamptz`;
}

// ── Column spec ──────────────────────────────────────────────────────────────

const COLS = [
  'id', 'source', 'source_finding_id', 'type', 'title', 'description',
  'resource_type', 'resource_id', 'resource_name', 'resource_arn',
  'platform', 'cloud_provider', 'region', 'account_id', 'account_name',
  'environment_type', 'static_severity', 'severity',
  'ai_risk_score', 'ai_risk_level', 'ai_risk_rationale', 'ai_contextual_factors',
  'cvss', 'cvss_vector', 'epss', 'exploit_available',
  'cves', 'mitre_tactics', 'mitre_techniques', 'compliance_mappings',
  'remediation', 'auto_remediatable', 'category',
  'status', 'workflow_status', 'suppressed',
  'service_name', 'line_of_business',
  'first_found_at', 'last_seen_at', 'sla_breach_date', 'due_date',
  'deduplication_key', 'canonical_rule_id',
];

function findingToValues(f) {
  return [
    esc(f.id), esc(f.source), esc(f.source_finding_id), esc(f.type),
    esc(f.title), esc(f.description),
    esc(f.resource_type), esc(f.resource_id), esc(f.resource_name), esc(f.resource_arn),
    esc(f.platform), esc(f.cloud_provider), esc(f.region), esc(f.account_id), esc(f.account_name),
    esc(f.environment_type), esc(f.static_severity), esc(f.severity),
    f.ai_risk_score ?? 'NULL', esc(f.ai_risk_level), esc(f.ai_risk_rationale),
    escArray(f.ai_contextual_factors),
    f.cvss ?? 'NULL', esc(f.cvss_vector), f.epss ?? 'NULL', f.exploit_available ? 'TRUE' : 'FALSE',
    escJsonb(f.cves), escArray(f.mitre_tactics), escArray(f.mitre_techniques),
    escJsonb(f.compliance_mappings),
    esc(f.remediation), f.auto_remediatable ? 'TRUE' : 'FALSE', esc(f.category),
    esc(f.status), esc(f.workflow_status), f.suppressed ? 'TRUE' : 'FALSE',
    esc(f.service_name), esc(f.line_of_business),
    escTimestamp(f.first_found_at), escTimestamp(f.last_seen_at),
    escTimestamp(f.sla_breach_date), escTimestamp(f.due_date),
    esc(f.deduplication_key), esc(f.canonical_rule_id),
  ].join(', ');
}

// ── Main (streaming) ─────────────────────────────────────────────────────────

const frameworks = [
  ['nist-csf', 'NIST CSF 2.0', 'NIST Cybersecurity Framework v2.0', '2.0', 'general', 108],
  ['pci-dss', 'PCI-DSS v4.0', 'Payment Card Industry Data Security Standard', '4.0', 'finance', 78],
  ['hipaa', 'HIPAA Security Rule', 'Health Insurance Portability and Accountability Act', '2013', 'healthcare', 75],
  ['iso-27001', 'ISO 27001:2022', 'Information Security Management System', '2022', 'general', 93],
  ['iso-42001', 'ISO 42001:2023', 'Artificial Intelligence Management System', '2023', 'ai', 42],
  ['tisax', 'TISAX', 'Trusted Information Security Assessment Exchange', '6.0', 'automotive', 66],
  ['cis', 'CIS Benchmarks v8.0', 'Center for Internet Security Benchmarks', '8.0', 'general', 153],
  ['soc2', 'SOC 2 Type II', 'Service Organization Control 2', 'Type II', 'general', 64],
];

async function main() {
  const inputPath = join(IN_DIR, 'findings.json');
  log(`Streaming ${inputPath}...`);

  const out = createWriteStream(OUT_FILE);
  const w = (line) => out.write(line + '\n');

  w('-- Generated by scripts/seed-postgres.mjs (streaming mode)');
  w(`-- Generated: ${new Date().toISOString()}`);
  w('');
  w('BEGIN;');
  w('');

  if (TRUNCATE) {
    w('-- Clear existing data (cascade to compliance_mappings)');
    w('TRUNCATE findings CASCADE;');
    w('');
  }

  w('-- Ensure compliance frameworks exist');
  for (const [id, name, desc, ver, cat, controls] of frameworks) {
    w(`INSERT INTO compliance_frameworks (id, name, description, version, category, total_controls, controls_passing, controls_failing, score)`);
    w(`  VALUES (${esc(id)}, ${esc(name)}, ${esc(desc)}, ${esc(ver)}, ${esc(cat)}, ${controls}, ${Math.round(controls * 0.72)}, ${Math.round(controls * 0.28)}, ${(72 + Math.random() * 8).toFixed(2)})`);
    w(`  ON CONFLICT (id) DO UPDATE SET total_controls = EXCLUDED.total_controls, score = EXCLUDED.score;`);
  }
  w('');

  // ── Stream findings + compliance mappings ────────────────────────────────
  let batch = [];
  let totalFindings = 0;
  let mappingCount = 0;

  function flushBatch() {
    if (batch.length === 0) return;

    // Findings INSERT
    w(`INSERT INTO findings (${COLS.join(', ')}) VALUES`);
    const rows = batch.map(f => `  (${findingToValues(f)})`);
    w(rows.join(',\n'));
    w('ON CONFLICT (id) DO NOTHING;');
    w('');

    // Compliance mappings INSERT
    const mappingRows = [];
    for (const f of batch) {
      if (!f.compliance_mappings || f.compliance_mappings.length === 0) continue;
      for (const m of f.compliance_mappings) {
        mappingRows.push(`  (${esc(f.id)}, ${esc(m.framework_id)}, ${esc(m.control_id)}, ${esc(m.control_title)}, ${esc(m.section)}, ${esc(m.severity)})`);
        mappingCount++;
      }
    }
    if (mappingRows.length > 0) {
      w('INSERT INTO compliance_mappings (finding_id, framework_id, control_id, control_title, section, severity) VALUES');
      w(mappingRows.join(',\n'));
      w('ON CONFLICT (finding_id, framework_id, control_id) DO NOTHING;');
      w('');
    }

    batch = [];
  }

  for await (const finding of streamJsonArray(inputPath)) {
    batch.push(finding);
    totalFindings++;
    if (batch.length >= BATCH_SIZE) flushBatch();
  }
  flushBatch(); // remaining

  w('COMMIT;');
  w('');
  w(`-- Summary: ${totalFindings} findings, ${mappingCount} compliance mappings, ${frameworks.length} frameworks`);

  await new Promise((resolve) => out.end(resolve));

  const { statSync } = await import('fs');
  const sizeMB = (statSync(OUT_FILE).size / 1024 / 1024).toFixed(1);
  log(`Wrote ${OUT_FILE} (${sizeMB} MB)`);
  log(`  ${totalFindings} findings, ${mappingCount} compliance mappings, ${frameworks.length} frameworks`);
  log(`  Load with: psql "$DATABASE_URL" < ${OUT_FILE}`);
}

main().catch(err => { console.error(err); process.exit(1); });
