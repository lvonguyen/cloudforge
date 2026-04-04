# Security Graph Target Architecture

**Date:** 2026-03-30  
**Context:** CloudForge graph/attack-path architecture follow-up after industry CSPM landscape review

## Executive Summary

Cloudforge should not treat graph rendering as a purely visual problem.

The main gap is architectural:

1. The repo already has a graph query surface and graph-adjacent UI.
2. The current attack-path pipeline is still heuristic and finding-centric.
3. A production-grade CSPM experience requires a live security graph, graph-native controls, and issue materialization before the attack-path visualization layer.

## Current State

### What exists

- Read-only PuppyGraph query proxy:
  - `cmd/server/handlers_graph.go`
  - `internal/graph/client.go`
- Local PuppyGraph schema over PostgreSQL:
  - `deploy/docker/puppygraph/schema.json`
- Heuristic attack-path generation:
  - `cmd/server/attackpath.go`
- Frontend graph shells based on ReactFlow:
  - `frontend/src/pages/ops/SecurityGraph.tsx`
  - `frontend/src/pages/ops/AttackPaths.tsx`
  - `frontend/src/components/attack-path/AttackPathMiniGraph.tsx`

### What is missing

- No graph-native `Control` concept that evaluates toxic combinations over a live graph.
- No first-class `Issue` entity produced by graph control matches.
- No tenant-scoped event pipeline that incrementally upgrades or downgrades issues as graph state changes.
- No live frontend graph neighborhood query path used by the main graph UX.

## PuppyGraph Assessment

### Best current role

PuppyGraph fits best as:

- a federated query and analyst exploration layer
- a bridge for querying relational data as a graph during migration
- a low-friction local and demo environment

### Why it is not enough by itself

Current repo usage is too thin for PuppyGraph alone to be considered the security graph source of truth:

- the local schema only exposes `finding`, `resource`, and `compliance_framework`
- attack paths are still computed separately from graph traversals
- the frontend does not materially consume live graph neighborhoods for the main UX

If Cloudforge wants live Controls -> Issues -> Attack Paths semantics, it still needs:

- a richer graph data model
- an event-driven update path
- incremental recomputation of issues and path state

## Neptune Assessment

Official AWS reference points worth carrying forward:

- AWS published a Neptune-backed security graph case study showing the reference architecture:
  - https://aws.amazon.com/solutions/case-studies/wiz-neptune/
- Neptune supports Gremlin and openCypher for property graph access:
  - https://docs.aws.amazon.com/neptune/latest/userguide/get-started-access-graph.html
- Neptune Streams provides ordered graph change capture:
  - https://docs.aws.amazon.com/neptune/latest/userguide/streams.html

### Where Neptune fits

Neptune is a better candidate when Cloudforge wants:

- a primary graph engine for a tenant-scoped security graph
- graph-native traversal as part of the actual issue-detection pipeline
- graph change streams feeding downstream recompute or notification flows
- AWS-native managed operations at larger scale

### What Neptune does not remove

Neptune does not eliminate the need for:

- a control language
- issue lifecycle/state management
- raw finding/resource storage outside the graph when appropriate
- event routing, caching, and UI fanout

## Recommended Target Shape

### Near-term recommendation

Adopt a hybrid path:

1. Keep PuppyGraph for local graph querying, prototyping, and analyst exploration.
2. Define the missing domain model now:
   - `SecurityGraph` node and edge taxonomy
   - `Control`
   - `Issue`
   - `AttackPathProjection`
3. Move the frontend toward live neighborhood queries instead of client-built graph fabrication.

### Medium-term recommendation

If the product direction remains AWS-first and graph-native issue generation becomes core, evaluate Neptune as the primary graph layer for production while demoting PuppyGraph to:

- dev/demo exploration
- federation over relational side data
- ad hoc analyst queries

## Staged Migration

### Stage 1

- Expand graph schema beyond findings/resources.
- Add graph-native control definitions and issue materialization.
- Keep existing heuristic paths for backward compatibility.

### Stage 2

- Introduce tenant-scoped event triggers for graph and issue recompute.
- Add live graph neighborhood APIs for the frontend.
- Start rendering Issues and Attack Paths from graph-native outputs.

### Stage 3

- Promote the graph engine to primary computation path.
- Relegate heuristic attack-path generation to fallback or delete it.
- Unify graph UX across Security Graph, Findings detail, Investigations, and Attack Paths.

## Decision Guidance

### Keep PuppyGraph as primary only if

- graph remains mostly a read/query overlay on relational data
- issue generation stays outside the graph engine
- demo and analyst workflows matter more than graph-native correctness

### Move to Neptune-primary if

- graph-native controls become the heart of issue detection
- incremental graph updates and event-driven state transitions matter
- tenant-scoped live risk posture becomes a product requirement, not a future aspiration
