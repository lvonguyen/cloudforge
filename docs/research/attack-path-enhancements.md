# Wiz Attack Path Analysis: Architecture Insights & Project Enhancement Roadmap

**Author:** Liem Vo-Nguyen | **Date:** 2026-02-26
**Targets:** csmp-aggregator, AgentGuard | **Context:** Enterprise multi-cloud (3,500+ envs)

---

## 1. Wiz's Secret Sauce — Architecture Deep Dive

### Graph Database Foundation
Wiz built their security platform on **Amazon Neptune** (managed graph DB), processing **1.2 billion asset relationships daily** across hundreds of Neptune clusters spanning 20+ AWS regions. The graph stores hundreds of billions of relationships representing the full cloud estate — workloads, identities, networks, data stores, and their interconnections.

**Why graph matters:** Traditional CSPM tools evaluate findings in isolation. A misconfigured S3 bucket is "medium." An overly permissive IAM role is "medium." A known CVE on an EC2 instance is "medium." But chain them together — internet-exposed EC2 with CVE → lateral movement via overprivileged role → exfiltrate from misconfigured S3 containing PII — and you have a **critical attack path**. Graph traversal finds these chains; relational queries cannot.

### Toxic Combinations Methodology
Wiz's core differentiator is **toxic combination detection** — the insight that multiple low/medium-severity issues chained together create critical risk. This reduces noise dramatically: 10,000+ individual findings collapse to dozens of actionable attack paths prioritized by actual exploitability.

The approach evaluates **7 risk dimensions** simultaneously:
1. **Network exposures** — internet-facing assets, open ports, missing WAF/NACLs
2. **Vulnerabilities** — CVEs with reachability analysis (not just presence)
3. **Misconfigurations** — CIS/benchmark deviations with blast radius context
4. **Identities** — overprivileged roles, cross-account trust chains, federation gaps
5. **Data** — sensitive data classification, encryption state, access patterns
6. **Secrets** — exposed credentials, hardcoded keys, rotation failures
7. **Malware** — known malicious signatures, suspicious behaviors

### Contextual Risk Scoring (Beyond CVSS)
Wiz scores risk using multiple contextual factors:
- **Severity** of individual findings
- **Asset criticality** (crown jewel proximity)
- **Network exposure** (reachability from internet/other accounts)
- **Threat intelligence** (active exploitation in the wild)
- **Compliance requirements** (regulatory overlay)
- **Business impact** (data sensitivity, service criticality)
- **Cloud context** (multi-account relationships, cross-cloud paths)

### Agentless + Runtime Hybrid
Core scanning is **fully agentless** — API-based snapshot scanning of the entire stack. **Wiz Defend** adds optional eBPF-based runtime sensors for real-time threat detection, creating a hybrid model: agentless for posture + agent-based for runtime.

### Cross-Cloud Single Graph
All clouds (AWS, Azure, GCP) feed into a **single unified graph**, enabling detection of cross-cloud and cross-account lateral movement paths that cloud-native tools miss entirely.

### AI Security Graph (AI-SPM)
Wiz extended the graph model for AI workloads — mapping AI models, training infrastructure, data pipelines, serving endpoints, and associated identities as interconnected graph nodes. This enables AI-specific attack path detection: compromised training data → poisoned model → production inference endpoint.

---

## 2. csmp-aggregator Enhancements

### Current State (from CLAUDE.md)
Go-based CSPM aggregator with Claude Opus 4.6 AI scoring. Aggregates findings across 3,500+ environments (multiple AWS Organizations, 350+ GCP projects, 750+ Azure subscriptions).

### Enhancement Roadmap

#### E1: Graph Database Layer (High Priority)
**What:** Add Neo4j or Amazon Neptune as a relationship store alongside existing finding storage.

**Why:** The aggregator already ingests findings from 3,500+ environments across multiple cloud accounts. Today those findings are correlated by metadata (account, resource ID). A graph layer enables relationship-aware correlation — "this finding on resource A matters because resource A has a trust relationship to resource B which holds sensitive data."

**Implementation approach:**
- Model cloud resources as nodes (EC2, S3, IAM Role, GCP VM, Azure VM, etc.)
- Model relationships as edges (network reachability, IAM trust, data access, service dependency)
- Ingest relationship data from cloud APIs alongside findings (VPC flow logs, IAM policies, resource policies, network configs)
- Neo4j is the pragmatic choice — mature Go driver (`neo4j/neo4j-go-driver`), Cypher query language, runs locally for dev. Neptune for production AWS deployment.
- Start with AWS (largest org count), expand to GCP/Azure

**Graph schema starter:**
```
(:Asset {id, type, account, cloud, region})
(:Finding {id, severity, source, cve})
(:Identity {arn, type, permissions[]})
(:DataStore {id, classification, encrypted})

(Asset)-[:HAS_FINDING]->(Finding)
(Asset)-[:CAN_REACH]->(Asset)  // network reachability
(Identity)-[:CAN_ASSUME]->(Identity)  // role chaining
(Identity)-[:CAN_ACCESS]->(DataStore)
(Asset)-[:RUNS_AS]->(Identity)
```

#### E2: Toxic Combination Detection (High Priority)
**What:** Implement graph traversal queries that identify multi-hop attack paths.

**Why:** This is the core Wiz differentiator. Instead of presenting 10K findings to security teams, surface the 20-30 attack paths that actually matter. Directly supports the tier-based remediation model (T1/T2/T3).

**Implementation approach:**
- Define attack path templates as Cypher query patterns:
  ```cypher
  // Internet-exposed → vulnerable → overprivileged → sensitive data
  MATCH path = (entry:Asset)-[:CAN_REACH*1..4]->(target:DataStore)
  WHERE entry.internetExposed = true
    AND ANY(f IN [(entry)-[:HAS_FINDING]->(f) | f] WHERE f.severity >= 'HIGH')
    AND ANY(hop IN nodes(path) WHERE hop:Identity AND hop.overprivileged = true)
    AND target.classification IN ['PII', 'PHI', 'FINANCIAL']
  RETURN path, length(path) as hops
  ORDER BY hops ASC
  ```
- Create a library of attack path patterns mapped to MITRE ATT&CK tactics
- Score paths by: hop count (shorter = more exploitable), finding severities along the path, target asset criticality, exposure type

#### E3: Contextual Risk Scoring Enhancement (Medium Priority)
**What:** Extend the existing Claude Opus 4.6 AI scoring with graph-derived context.

**Why:** The AI scoring already differentiates csmp-aggregator. Adding graph context (relationship data, blast radius, crown jewel proximity) to the AI prompt gives the model richer signal for prioritization — moving from "how severe is this finding?" to "how dangerous is this finding given what it can reach?"

**Implementation approach:**
- Before AI scoring, run graph queries to determine: blast radius (what can be reached from the affected resource), crown jewel proximity (hops to sensitive data/critical services), identity chain depth (how many role assumptions are possible)
- Include graph context in the AI scoring prompt as structured data
- Weight scoring factors: exploit availability > network exposure > identity chain depth > data sensitivity

#### E4: Cross-Account Path Analysis (Medium Priority)
**What:** Map trust relationships across multiple AWS Organizations, 350+ GCP projects, 750+ Azure subscriptions.

**Why:** Cross-account lateral movement is the blind spot for cloud-native CSPM tools. With 3,500+ environments across multiple orgs and subscriptions, cross-account trust chains are a significant attack surface that no single-account tool can see.

**Implementation approach:**
- Ingest IAM trust policies, resource policies, and cross-account roles
- Map VPC peering, Transit Gateway attachments, PrivateLink connections
- For GCP: organization policies, shared VPCs, service account impersonation chains
- For Azure: management group hierarchy, cross-subscription RBAC, service principal relationships
- Graph edges span account boundaries — this is where the unified graph pays off

#### E5: Findings-to-Paths Deduplication (Low Priority)
**What:** Group related findings into attack paths and deduplicate notification/tracking.

**Why:** Directly reduces ticket volume while increasing signal quality — supporting high closure rates. Instead of 5 tickets for 5 related findings, create 1 ticket for the attack path with remediation that breaks the chain.

---

## 3. AgentGuard Enhancements

### Current State (from CLAUDE.md)
AI security governance — greenfield positioning project.

### Enhancement Roadmap

#### A1: AI-SPM Graph Model (High Priority)
**What:** Model AI workloads as graph nodes with security-relevant relationships, mirroring Wiz's AI Security Graph approach.

**Why:** AI workloads have unique attack surfaces: training data poisoning, model supply chain compromise, inference endpoint abuse, prompt injection chains. Graph-based modeling enables attack path detection specific to AI infrastructure.

**Node types:**
```
(:AIModel {id, framework, version, source, integrity_hash})
(:TrainingData {id, source, classification, lineage})
(:ServingEndpoint {id, url, auth_method, rate_limited})
(:ModelRegistry {id, type, access_controls})
(:Pipeline {id, type, stages[], triggers})
```

**Relationship types:**
```
(TrainingData)-[:TRAINS]->(AIModel)
(AIModel)-[:DEPLOYED_TO]->(ServingEndpoint)
(AIModel)-[:STORED_IN]->(ModelRegistry)
(Pipeline)-[:PRODUCES]->(AIModel)
(Identity)-[:CAN_MODIFY]->(TrainingData)
(Identity)-[:CAN_INVOKE]->(ServingEndpoint)
```

#### A2: AI-Specific Attack Path Patterns (High Priority)
**What:** Define and detect AI-specific toxic combinations.

**Example patterns:**
- **Training data poisoning path:** Overprivileged identity → write access to training data → model retrain trigger → production serving endpoint
- **Model supply chain compromise:** Public model registry → unverified model pull → deployment pipeline → production inference
- **Inference abuse chain:** Unauthenticated endpoint → no rate limiting → prompt injection → data exfiltration via model output
- **Shadow AI path:** Unmanaged SageMaker notebook → internet-facing → attached to production IAM role → access to production data stores

#### A3: Governance Policy Engine (Medium Priority)
**What:** Define AI security policies as graph constraints — violations are paths that shouldn't exist.

**Example policies:**
- "No AI model trained on PII data may be served on internet-facing endpoints without DLP scanning"
- "No model registry may accept pushes from identities outside the ML engineering team"
- "All training data sources must have lineage tracked to an approved data catalog entry"

---

## 4. Interview Talking Points

### Connecting Wiz Knowledge to Enterprise CSPM Experience

**"Why graph-based security matters at scale":**
> "Managing CSPM across 3,500+ cloud environments — multiple AWS Organizations, 350+ GCP projects, 750+ Azure subscriptions — traditional finding-by-finding remediation doesn't scale. Achieving high closure rates requires tier-based automation, but the next evolution is relationship-aware prioritization. Wiz proved with their Neptune-backed graph processing 1.2B relationships daily that the real signal isn't individual findings — it's the toxic combinations. I'm building toward that with csmp-aggregator's graph layer."

**"Toxic combinations reduce noise":**
> "The challenge at enterprise scale isn't finding issues — it's prioritizing them. 10,000+ medium-severity findings across 3,500+ environments creates alert fatigue. Wiz's insight is that chaining those findings through graph traversal surfaces the 20-30 paths that actually represent breach risk. That's the difference between 'this S3 bucket is misconfigured' and 'this misconfigured S3 bucket containing PHI is reachable through a 3-hop role chain from an internet-exposed instance with a known CVE.'"

**"Cross-cloud is the blind spot":**
> "Most cloud-native tools operate within a single cloud's blast radius. Spanning AWS, GCP, and Azure simultaneously, cross-cloud trust relationships and lateral movement paths are invisible to single-cloud tools. That's why a unified graph approach — which Wiz pioneered — is essential for organizations with multi-cloud estates."

**"AI-SPM is the next frontier":**
> "With AgentGuard, I'm applying graph-based security modeling to AI workloads — mapping models, training data, serving endpoints, and identities as interconnected nodes. The same toxic combination logic applies: an overprivileged identity with write access to training data, connected to an auto-retrain pipeline, connected to a production serving endpoint is an attack path. Wiz recognized this with their AI Security Graph extension."

---

## 5. Implementation Priority Matrix

| Enhancement | Project | Priority | Effort | Impact |
|---|---|---|---|---|
| E1: Graph DB Layer | csmp-aggregator | 🔴 High | Large | Foundation for all graph features |
| E2: Toxic Combinations | csmp-aggregator | 🔴 High | Medium | Core differentiator |
| A1: AI-SPM Graph | AgentGuard | 🔴 High | Medium | Greenfield positioning |
| E3: Contextual AI Scoring | csmp-aggregator | 🟡 Medium | Small | Enhances existing AI scoring |
| A2: AI Attack Patterns | AgentGuard | 🔴 High | Medium | Concrete governance value |
| E4: Cross-Account Paths | csmp-aggregator | 🟡 Medium | Large | Multi-cloud differentiator |
| A3: Governance Policies | AgentGuard | 🟡 Medium | Medium | Policy-as-code alignment |
| E5: Finding Dedup | csmp-aggregator | 🟢 Low | Small | Operational efficiency |

**Recommended sequence:** E1 → E2 → A1 → E3 → A2 → E4 → A3 → E5

E1 (graph DB layer) is the foundation — everything else builds on it. E2 (toxic combinations) delivers the most visible value. A1 (AI-SPM graph) positions AgentGuard with a concrete, differentiated capability.

---

## References
- Wiz Security Graph architecture (Amazon Neptune backend, 1.2B relationships/day)
- Wiz toxic combinations methodology and 7 risk dimensions
- Wiz Defend hybrid agentless + eBPF runtime architecture
- Wiz AI-SPM and AI Security Graph capabilities
- Enterprise CSPM operational context: 3,500+ environments, tier-based remediation automation
