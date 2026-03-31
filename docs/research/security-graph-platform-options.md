# Security Graph Platform Options

**Date:** 2026-03-31  
**Scope:** `WG-A` security graph platform decision

## Current Repo Reality

- Attack paths are heuristic chains built from findings, not graph-native issue outputs.
  - See `cmd/server/attackpath.go`.
- The main graph UI is findings-derived and client-built.
  - See `frontend/src/pages/ops/SecurityGraph.tsx`.
- PuppyGraph is present as a read-only graph query surface over a thin relational projection.
  - See `cmd/server/handlers_graph.go`, `internal/graph/client.go`, `deploy/docker/puppygraph/schema.json`.

## Decision

### Near term

Keep **PuppyGraph** as:

- a federated graph query layer over relational data
- an analyst exploration surface
- a bridge while the graph-native Controls -> Issues model is defined

Do **not** treat PuppyGraph as the long-term source of truth for a live Wiz-like security graph without first proving it can support:

- tenant-scoped low-latency updates
- richer node/edge taxonomy
- issue materialization from graph state
- incremental recomputation when evidence changes

### Target state

If Cloudforge wants a true `Security Graph -> Controls -> Issues -> Attack Paths` architecture, **Amazon Neptune Database** is the stronger primary-engine candidate on AWS.

Recommended role split:

- **Aurora/Postgres**: high-volume raw findings, config snapshots, controls metadata, issues lifecycle, audit
- **Neptune Database**: tenant-scoped security graph and graph-native traversals
- **ElastiCache/Valkey**: diff/cache hot paths, scan comparison, transient recompute support
- **PuppyGraph**: optional analyst query/federation layer during transition

## Why

Wiz's published architecture is closer to this split than to a single federated query layer:

- Neptune stores the security graph
- Aurora stores high-volume data
- ElastiCache is used for scan-comparison offload
- Bedrock assists with remediation/investigation flows

## Eventing Direction

Explore AWS-native eventing in `WG-C`:

- **EventBridge Pipes** for simple source-to-target routing with filtering/enrichment
- **SNS/SQS fan-out** when explicit queue isolation per tenant or workstream is needed
- **Neptune Streams** if downstream consumers need graph-change notifications

## Guardrails

- Do not start with graph visual polish as the main investment.
- Define canonical node/edge taxonomy first.
- Define graph-native controls and issue lifecycle before replacing the current attack-path pipeline.
- Keep a fallback path while heuristic and graph-native outputs coexist.

## Source Links

- AWS case study: <https://aws.amazon.com/solutions/case-studies/wiz-neptune/>
- Neptune Streams: <https://docs.aws.amazon.com/neptune/latest/userguide/streams-change-formats.html>
- EventBridge Pipes: <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html>
- PuppyGraph docs: <https://docs.puppygraph.com/getting-started/>
