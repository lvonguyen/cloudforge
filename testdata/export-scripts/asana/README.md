# Asana Utilities

**Purpose:** Data normalization, bulk import, and remediation tracking for Asana CSPM tasks
**Updated:** 2025-12-11

---

## Directory Structure

```
1.2asana-utils/
├── data-cleansing/
│   ├── ingest_findings_to_csv.py    # Multi-cloud JSON → unified CSV
│   └── cleansed-imports/            # Output CSVs
└── remediation-utils/
    └── sync_findings_generic.py     # Asana sync & evidence upload
```

---

## Data Cleansing

**Script:** `data-cleansing/ingest_findings_to_csv.py`

```bash
python data-cleansing/ingest_findings_to_csv.py --execute
```

**Process:** Raw JSON → Deduplicate → Normalize schema → Enrich (env/platform/tier) → Unified CSV

**Unified CSV Columns:** Finding, Status, CSP, Severity, Tier, EnvType, EnvFriendlyName, EnvId, CreatedTime, FindingId, FindingIdShort, Region, ExecutionTeam, EstEffort, Tags

---

## Remediation Utilities

**Script:** `remediation-utils/sync_findings_generic.py`

```bash
export ASANA_ACCESS_TOKEN=$(python ../get_asana_token_keyvault.py)
python remediation-utils/sync_findings_generic.py --csv unified_findings.csv --update-comments
```

**Features:** Task matching, status updates, screenshot attachment, completion marking

---

## Stats

| Period | AWS | Azure | GCP | Total |
|--------|-----|-------|-----|-------|
| Baseline (Oct 2025) | 216 | 50 | 381 | 647 |
| Current (Dec 2025) | 151 | 46 | 462 | 659 |

---

**Data Flow:** Raw Export → Cleansing → Unified CSV → Asana Import → Remediation Tracking

**Owner:** Enterprise Security TFT | **Prepared For:** CS.01 L2 Signoff (Dec 12, 2025)
