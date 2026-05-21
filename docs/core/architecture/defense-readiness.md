---
sidebar_position: 4
title: Defense Readiness Demo
---

# Defense Readiness Demo

CloudForge includes a defense-adjacent demo lane for explaining how a fast-moving engineering organization can make cloud security, evidence collection, and compliance-oriented remediation visible without pretending to operate a certified government environment.

This lane uses synthetic infrastructure data only. It does not process classified information, Controlled Unclassified Information (CUI), ITAR-controlled technical data, customer data, or government data. Framework references are educational control mappings, not legal determinations or certification claims.

## Positioning

The scenario models a defense startup preparing cloud and collaboration boundaries for regulated work:

- AWS commercial, AWS GovCloud, Azure commercial, and Microsoft GCC High are modeled as separate target boundaries.
- Findings are mapped to CMMC, NIST SP 800-171, FedRAMP, DoD Cloud SRG, and export-control-aware evidence expectations.
- The operator view turns broad compliance pressure into engineering actions: identity cleanup, logging retention, artifact controls, tagging, and CI/CD guardrails.
- The output is useful for interview storytelling because it shows technical judgment without claiming direct defense, classified, or certified compliance experience.

## Guardrails

Use this phrasing:

- "Synthetic defense-adjacent readiness workflow."
- "CMMC, NIST 800-171, FedRAMP, and export-control-inspired control mappings."
- "Demo data only; no CUI, classified, ITAR-controlled, customer, or government data."
- "Evidence acceleration and engineering guardrails, not a certification claim."

Avoid this phrasing:

- "FedRAMP compliant."
- "CMMC certified."
- "ITAR compliant."
- "Built for classified workloads."
- "Defense production experience."
- "GovCloud guarantees compliance."

## Evidence Pipeline

The demo lane adds a layer over existing CloudForge primitives:

1. Cloud posture data arrives from AWS, Azure, GCP, and synthetic GovCloud/GCC High targets.
2. Findings are normalized and mapped to control evidence expectations.
3. Threat intelligence enriches vulnerability context using EPSS, CISA KEV, Vulnrichment, SSVC, and structured STIX/TAXII concepts.
4. Policy-as-code checks classify restricted-label risk, missing tags, logging gaps, and identity drift.
5. Remediation queues produce ticketable engineering work with a clear control rationale.
6. Dashboards show whether cloud state, tickets, scan output, and evidence still agree.

See [defense-readiness-pipeline.mmd](../diagrams/defense-readiness-pipeline.mmd) for the diagram source.

## Synthetic Findings

The public demo keeps the static Pages payload intentionally small while still showing a meaningful defense-readiness slice:

- `/mock/findings.json` serves 500 findings for the portfolio UI; 14 of those are curated Azure Government, GCP Assured Workloads-style, and AWS GovCloud synthetic findings.
- `/mock/attack-paths.json` serves the precomputed path portfolio; the defense slice prepends five explicit attack paths across migration ingress, CI/CD identity, artifact storage, audit integrity, and rollback-first remediation.
- The larger generated corpus remains available for backend or R2-backed demos, but the production Pages experience prioritizes fast, inspectable static assets.
- All defense records are synthetic and include `synthetic-only`, `synthetic-cui`, and simulated control-scope tags so the story stays useful without claiming certified government operations.

| Severity | Finding | Evidence Mapping | Engineering Action |
| --- | --- | --- | --- |
| High | `admin-bastion-sg` permits internet SSH | CMMC AC.L2-3.1.1, FedRAMP AC-4 | Restrict ingress to VPN/ZTNA, require session logging |
| High | `prototype-artifacts-prod` lacks enforced KMS policy | NIST 800-171 03.13.11, FedRAMP SC-28 | Enforce CMK, public-access block, and object audit logs |
| Medium | Commercial CI artifact lacks restricted-label gate | ITAR/EAR Boundary EXP-01 | Add classifier, approval gate, and retention rule |
| Medium | CloudTrail log validation missing in one mission account | FedRAMP AU-9, CMMC AU.L2-3.3.1 | Enable org trail validation and immutable retention |
| Low | Resources missing owner and classification tags | CMMC CM.L2-3.4.2, NIST CSF ID.AM | Add policy-as-code tag checks and weekly evidence export |

## Source Anchors

- AWS says GovCloud supports architecture for regimes including FedRAMP High, DoD SRG, CMMC, ITAR, and EAR, but customer configuration still determines the system outcome: [AWS GovCloud compliance](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-compliance.html).
- Microsoft describes GCC High as a purpose-built platform for CMMC-oriented government cloud requirements and notes use cases involving CUI, CJIS, ITAR, and EAR: [Microsoft CMMC guidance](https://learn.microsoft.com/en-us/compliance/us-government/gov-cmmc).
- NIST SP 800-171 Rev. 3 defines recommended requirements for protecting CUI in nonfederal systems and organizations: [NIST CSRC publication](https://csrc.nist.gov/pubs/sp/800/171/r3/final).
- FedRAMP documentation defines the program's role in assessment, authorization, and continuous monitoring for federal cloud services: [FedRAMP authority and responsibility](https://www.fedramp.gov/docs/authority/).
- CISA describes KEV as its authoritative catalog of vulnerabilities exploited in the wild: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities).
- FIRST EPSS estimates the probability that a published CVE will be exploited in the wild in the next 30 days: [FIRST EPSS](https://www.first.org/epss/).
- CISA SSVC provides vulnerability decision support using exploitation, safety impact, and product prevalence: [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc).
- CISA Vulnrichment adds CVE context and SSVC decision points: [CISA Vulnrichment](https://www.cisa.gov/news-events/news/unlocking-vulnrichment-enriching-cve-data).
