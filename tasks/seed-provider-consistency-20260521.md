# Seed Provider Consistency Check — 2026-05-21

## Scope

Follow-up for WS-8 / EC-01 from `tasks/qa-visual-cloudguard-20260521.md`.

The confirmed issue was generated seed data that could pair provider-specific finding text with the wrong `cloud_provider`, for example Azure Cosmos DB copy showing under AWS/GCP providers. The current fix targets the seed sources, not the ignored generated seed output.

## Fix

- `scripts/aegis-seed.mjs`
  - Synthetic padding now selects the provider before selecting a real finding template.
  - Synthetic templates are constrained to the same provider as the generated finding.
  - Synthetic resource IDs/ARNs are provider-native instead of always AWS-style.
  - Azure `microsoft.documentdb` / Cosmos resource IDs now map to `database`.
  - AWS `AwsRdsDbCluster` / DocumentDB resources now map to `database`.
  - Azure provider extraction is now case-insensitive, preserving lowercase `microsoft.documentdb/databaseaccounts` inputs.
- `scripts/transform-real-findings.mjs`
  - Azure `documentdb` / Cosmos resources now map to `database`.
  - AWS `AwsRdsDbCluster` / DocumentDB resources now map to `database`.
- `testdata/transform_findings.py`
  - Scrubbed Azure `microsoft.documentdb/databaseaccounts` resources now map to `database`.
  - Scrubbed AWS DocumentDB/DocDB resources now map to `database`.

## Verification

Generated a synthetic-padded sample without touching the ignored local 300K seed:

```bash
mkdir -p /tmp/cloudforge-seed-check-20260521
node scripts/aegis-seed.mjs --count 10000 --out /tmp/cloudforge-seed-check-20260521 --seed 42
```

Result:

```json
{
  "total": 10000,
  "cosmos": 152,
  "badCosmosProvider": 0,
  "badCosmosType": 0,
  "badAzureArn": 0,
  "badGcpArn": 0,
  "awsTextOnNonAws": 0,
  "azureTextOnNonAzure": 0
}
```

Static checks:

```bash
node --check scripts/aegis-seed.mjs
node --check scripts/transform-real-findings.mjs
python3 -m py_compile testdata/transform_findings.py
```

Full 300K regeneration for the GCP trial storage landing zone:

```bash
node --max-old-space-size=6144 scripts/aegis-seed.mjs \
  --count 300000 \
  --out /tmp/cloudforge-gcp-seed-20260521 \
  --full \
  --seed 42
node scripts/seed-postgres.mjs \
  --in /tmp/cloudforge-gcp-seed-20260521 \
  --out /tmp/cloudforge-gcp-seed-20260521/seed-findings.sql
node scripts/seed-resources.mjs \
  --in /tmp/cloudforge-gcp-seed-20260521 \
  --out /tmp/cloudforge-gcp-seed-20260521/seed-resources.sql
```

Provider-aware full-corpus audit:

```json
{
  "total": 300000,
  "azureDoc": 2127,
  "badAzureDoc": 0,
  "awsDoc": 22,
  "badAwsDoc": 0,
  "badAzureArn": 0,
  "badGcpArn": 0
}
```

Artifacts uploaded:

```text
gs://cloudforge-seed-418834332294-us-central1/datasets/20260521-full-300k/
```

## Remaining

The committed repo does not track `testdata/seed/*.json` or `*.sql`; the GCP trial storage artifacts are staged, but live database reload remains pending operational work.
