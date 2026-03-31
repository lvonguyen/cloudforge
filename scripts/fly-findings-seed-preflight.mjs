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
  '010_integration_runtime_state.sql',
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
const flySecretSyncScript = exists('scripts/fly-sync-runtime-secrets.sh')
  ? read('scripts/fly-sync-runtime-secrets.sh')
  : ''
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
const makefileMigrateOnly001 = /migrate:\s*\n(?:.*\n)*\s*psql\s+\$\(DATABASE_URL\)\s+-f\s+migrations\/001_exception_management\.sql/m.test(makefile)
const migrationUsesGenRandomUUID = /gen_random_uuid\(\)/.test(migration001)
const seedDefault20000 = /const TARGET_COUNT = parseInt\(getArg\('--count'\) \?\? '20000'/.test(seedScript)
const fullModeMentioned = /--full/.test(seedScript)
const seedPostgresGeneratesSql = /Generate SQL seed file/.test(seedPostgres) && /psql "\$DATABASE_URL" < /.test(seedPostgres)
const seedResourcesExists = seedResources.length > 0
const syncScriptExists = flySecretSyncScript.length > 0
const syncScriptSetsDatabaseUrl = /add_secret_ref "AEGIS_DATABASE_URL"/.test(flySecretSyncScript)
const syncScriptSetsFindingsSource = /add_plain_value "FINDINGS_SOURCE"/.test(flySecretSyncScript)
const syncScriptDefaultsToMock = /FINDINGS_SOURCE="\$\{FINDINGS_SOURCE:-mock\}"/.test(flySecretSyncScript)
const syncScriptSetsGreyNoise = /add_secret_ref "GREYNOISE_API_KEY"/.test(flySecretSyncScript)
const syncScriptSetsHIBP = /add_secret_ref "HIBP_API_KEY"/.test(flySecretSyncScript)
const syncScriptSetsOTX = /add_secret_ref "OTX_API_KEY"/.test(flySecretSyncScript)
const syncScriptSetsThreatFox = /add_secret_ref "THREATFOX_AUTH_KEY"/.test(flySecretSyncScript)

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
  boolCheck(syncScriptExists, 'Fly runtime secret sync script exists', 'restore or add scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsDatabaseUrl, 'Fly runtime sync can inject AEGIS_DATABASE_URL via secrets', 'add AEGIS_DATABASE_URL handling to scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsFindingsSource, 'Fly runtime sync can control FINDINGS_SOURCE explicitly', 'add FINDINGS_SOURCE handling to scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptDefaultsToMock, 'Fly runtime sync defaults FINDINGS_SOURCE to mock until cutover is explicit', 'default FINDINGS_SOURCE to mock in scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsGreyNoise, 'Fly runtime sync can inject GREYNOISE_API_KEY via secrets', 'add GREYNOISE_API_KEY handling to scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsHIBP, 'Fly runtime sync can inject HIBP_API_KEY via secrets', 'add HIBP_API_KEY handling to scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsOTX, 'Fly runtime sync can inject OTX_API_KEY via secrets', 'add OTX_API_KEY handling to scripts/fly-sync-runtime-secrets.sh'),
  boolCheck(syncScriptSetsThreatFox, 'Fly runtime sync can inject THREATFOX_AUTH_KEY via secrets', 'add THREATFOX_AUTH_KEY handling to scripts/fly-sync-runtime-secrets.sh'),
]

const warnings = []

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
if (syncScriptExists && !syncScriptDefaultsToMock) {
  warnings.push('Fly runtime sync does not default FINDINGS_SOURCE to mock; enabling postgres before schema/data load will crash startup.')
}

const recommendedCommands = [
  `export DATABASE_URL='<postgres dsn>'`,
  `export AEGIS_DATABASE_URL="$DATABASE_URL"`,
  `export AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential'`,
  `psql "$DATABASE_URL" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'`,
  `for f in migrations/001_exception_management.sql migrations/002_findings_and_compliance.sql migrations/003_operations_and_agents.sql migrations/005_tenant_isolation.sql migrations/006_graph_support.sql migrations/007_security_graph.sql migrations/008_findings_assignment_context.sql migrations/009_finding_tickets.sql migrations/010_integration_runtime_state.sql; do psql "$DATABASE_URL" -f "$f"; done`,
  `node --max-old-space-size=6144 scripts/aegis-seed.mjs --count 300000 --out testdata/seed --full --seed 42`,
  `node scripts/seed-postgres.mjs --in testdata/seed --out /tmp/seed-findings.sql`,
  `psql "$DATABASE_URL" -f /tmp/seed-findings.sql`,
  `node scripts/seed-resources.mjs --in testdata/seed --out /tmp/seed-resources.sql`,
  `psql "$DATABASE_URL" -f /tmp/seed-resources.sql`,
  `# insert distinct accounts from findings or add a dedicated account seeding step`,
  `./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres`,
  `./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply`,
  `FINDINGS_SOURCE=postgres ./scripts/fly-sync-runtime-secrets.sh --include-integrations --include-threat-intel --include-postgres --apply`,
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
