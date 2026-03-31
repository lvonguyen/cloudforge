#!/usr/bin/env node
/**
 * fly-findings-seed-preflight.mjs
 *
 * Local-only safety check for the D19 full findings seed flow.
 * It does not require secrets, Fly access, or database access.
 *
 * Goals:
 * - verify the repo contains the expected migration and seed tooling
 * - surface operator-risk mismatches before a live Fly/Postgres cutover
 * - print the exact recommended command sequence with placeholders
 */

import { existsSync, readFileSync } from 'fs'
import { resolve } from 'path'

const repoRoot = process.cwd()
const hasJson = process.argv.includes('--json')

const requiredMigrations = [
  '001_exception_management.sql',
  '002_findings_and_compliance.sql',
  '003_operations_and_agents.sql',
  '005_tenant_isolation.sql',
  '006_graph_support.sql',
  '007_security_graph.sql',
  '008_findings_assignment_context.sql',
  '009_finding_tickets.sql',
]

function read(relPath) {
  return readFileSync(resolve(repoRoot, relPath), 'utf8')
}

function exists(relPath) {
  return existsSync(resolve(repoRoot, relPath))
}

function match(re, text) {
  const hit = text.match(re)
  return hit ? hit[1] : null
}

function boolCheck(ok, message, fix = null) {
  return { ok, message, fix }
}

const makefile = exists('Makefile') ? read('Makefile') : ''
const flyToml = exists('fly.toml') ? read('fly.toml') : ''
const migration001 = exists('migrations/001_exception_management.sql')
  ? read('migrations/001_exception_management.sql')
  : ''
const startup = exists('cmd/server/bootstrap_startup.go')
  ? read('cmd/server/bootstrap_startup.go')
  : ''
const seedScript = exists('scripts/aegis-seed.mjs') ? read('scripts/aegis-seed.mjs') : ''
const seedPostgres = exists('scripts/seed-postgres.mjs') ? read('scripts/seed-postgres.mjs') : ''
const seedResources = exists('scripts/seed-resources.mjs') ? read('scripts/seed-resources.mjs') : ''

const findingsTimeout = match(/findingsCtx,\s*findingsCancel := context\.WithTimeout\(context\.Background\(\),\s*(\d+)\*time\.Second\)/, startup)
const flyGracePeriod = match(/grace_period = "([^"]+)"/, flyToml)
const hasFindingsSourceEnv = /FINDINGS_SOURCE\s*=/.test(flyToml)
const hasDatabaseEnv = /AEGIS_DATABASE_URL\s*=/.test(flyToml)
const makefileMigrateOnly001 = /migrate:\s*\n(?:.*\n)*\s*psql\s+\$\(DATABASE_URL\)\s+-f\s+migrations\/001_exception_management\.sql/m.test(makefile)
const migrationUsesGenRandomUUID = /gen_random_uuid\(\)/.test(migration001)
const seedDefault20000 = /const TARGET_COUNT = parseInt\(getArg\('--count'\) \?\? '20000'/.test(seedScript)
const fullModeMentioned = /--full/.test(seedScript)
const seedPostgresGeneratesSql = /Generate SQL seed file/.test(seedPostgres) && /psql "\$DATABASE_URL" < /.test(seedPostgres)
const seedResourcesExists = seedResources.length > 0

const migrationChecks = requiredMigrations.map((name) =>
  boolCheck(exists(`migrations/${name}`), `migration present: ${name}`)
)

const checks = [
  ...migrationChecks,
  boolCheck(exists('scripts/aegis-seed.mjs'), 'full findings generator exists', 'restore or add scripts/aegis-seed.mjs'),
  boolCheck(exists('scripts/seed-postgres.mjs'), 'findings SQL generator exists', 'restore or add scripts/seed-postgres.mjs'),
  boolCheck(seedResourcesExists, 'resource SQL generator exists', 'restore or add scripts/seed-resources.mjs'),
  boolCheck(seedDefault20000, 'seed generator default count is still 20000, so D19 must pass --count 300000 explicitly'),
  boolCheck(fullModeMentioned, 'seed generator supports --full mode'),
  boolCheck(seedPostgresGeneratesSql, 'seed-postgres is SQL generation only and still requires explicit psql load'),
  boolCheck(migrationUsesGenRandomUUID, 'schema uses gen_random_uuid(), so pgcrypto bootstrap must be part of the operator runbook'),
  boolCheck(!makefileMigrateOnly001, 'Makefile migrate target is not stale', 'expand make migrate beyond 001 or avoid it for D19'),
  boolCheck(hasFindingsSourceEnv, 'fly.toml already declares FINDINGS_SOURCE', 'set FINDINGS_SOURCE=postgres during Fly deploy/cutover'),
  boolCheck(hasDatabaseEnv, 'fly.toml already declares AEGIS_DATABASE_URL', 'use Fly secrets for AEGIS_DATABASE_URL; do not hardcode it in fly.toml'),
]

const warnings = []

if (!hasFindingsSourceEnv) {
  warnings.push('fly.toml does not currently declare FINDINGS_SOURCE; D19 needs an explicit Fly secret or env override.')
}
if (!hasDatabaseEnv) {
  warnings.push('fly.toml does not declare AEGIS_DATABASE_URL; use Fly secrets and keep the current env-name contract consistent.')
}
if (makefileMigrateOnly001) {
  warnings.push('make migrate still only applies migration 001 and is not sufficient for a live D19 cutover.')
}
if (migrationUsesGenRandomUUID) {
  warnings.push('migrations use gen_random_uuid(); ensure CREATE EXTENSION IF NOT EXISTS pgcrypto runs before applying the schema.')
}
if (findingsTimeout) {
  warnings.push(`startup findings load is capped at ${findingsTimeout}s in bootstrap_startup.go; 300K rows may exceed that budget.`)
}
if (flyGracePeriod) {
  warnings.push(`Fly health check grace period is ${flyGracePeriod}; startup sync/backfill may need more headroom for the full corpus.`)
}
if (!seedResourcesExists) {
  warnings.push('resources cannot be backfilled from a dedicated seed script because scripts/seed-resources.mjs is missing.')
}

const recommendedCommands = [
  `export DATABASE_URL='<fly postgres url>'`,
  `export AEGIS_DATABASE_URL="$DATABASE_URL"`,
  `psql "$DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'`,
  `for f in migrations/001_exception_management.sql migrations/002_findings_and_compliance.sql migrations/003_operations_and_agents.sql migrations/005_tenant_isolation.sql migrations/006_graph_support.sql migrations/007_security_graph.sql migrations/008_findings_assignment_context.sql migrations/009_finding_tickets.sql; do psql "$DATABASE_URL" -f "$f"; done`,
  `node --max-old-space-size=6144 scripts/aegis-seed.mjs --count 300000 --out testdata/seed --full --seed 42`,
  `node scripts/seed-postgres.mjs --in testdata/seed --out /tmp/seed-findings.sql`,
  `psql "$DATABASE_URL" -f /tmp/seed-findings.sql`,
  `node scripts/seed-resources.mjs --in testdata/seed --out /tmp/seed-resources.sql`,
  `psql "$DATABASE_URL" -f /tmp/seed-resources.sql`,
  `# insert distinct accounts from findings or add a dedicated account seeding step`,
  `flyctl secrets set AEGIS_DATABASE_URL="$DATABASE_URL" FINDINGS_SOURCE=postgres -a cloudforge-api`,
  `flyctl deploy --remote-only`,
]

const result = {
  repoRoot,
  ready: checks.every((check) => check.ok) && warnings.length === 0,
  checks,
  warnings,
  findingsTimeoutSeconds: findingsTimeout ? Number(findingsTimeout) : null,
  flyGracePeriod,
  recommendedCommands,
}

if (hasJson) {
  console.log(JSON.stringify(result, null, 2))
  process.exit(result.ready ? 0 : 1)
}

console.log('D19 Fly/Postgres Preflight')
console.log(`Repo: ${repoRoot}`)
console.log('')
console.log('Checks:')
for (const check of checks) {
  const prefix = check.ok ? 'PASS' : 'FAIL'
  console.log(`- [${prefix}] ${check.message}`)
  if (!check.ok && check.fix) {
    console.log(`  fix: ${check.fix}`)
  }
}
console.log('')
if (warnings.length > 0) {
  console.log('Warnings:')
  for (const warning of warnings) {
    console.log(`- ${warning}`)
  }
  console.log('')
}
console.log('Recommended command sequence:')
for (const command of recommendedCommands) {
  console.log(`- ${command}`)
}

process.exit(result.ready ? 0 : 1)
