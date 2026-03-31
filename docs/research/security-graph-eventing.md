# Security Graph Eventing and Tenant Isolation

**Date:** 2026-03-31  
**Scope:** Cloudforge `WSG-3` eventing and change propagation for a live tenant-scoped security graph

## Summary

Cloudforge should treat eventing as a first-class part of the security-graph architecture, not a later integration detail.

The recommended AWS-native shape is:

1. **Raw producer events**
   - Cloud findings ingest
   - Asset inventory changes
   - Identity/trust changes
   - Exposure/runtime detections

2. **Tenant-scoped normalization**
   - Normalize into one internal event envelope with `tenant_id`, `resource_id`, `provider`, `event_type`, and `occurred_at`

3. **Durable per-tenant queueing**
   - Use **SQS FIFO** when ordering and duplicate suppression matter for a tenant/resource stream
   - Use **standard SQS** when throughput matters more than strict order

4. **Point-to-point processing with EventBridge Pipes**
   - Use Pipes where the workflow is one source -> one consumer path with filtering/enrichment

5. **Many-to-many fanout with SNS/EventBridge bus**
   - Use SNS or EventBridge event bus when multiple downstream systems must react to the same normalized event

6. **Graph and issue consumers**
   - graph projector
   - controls evaluator
   - issue materializer
   - cache invalidator
   - notification/ticket adapters

## Why This Shape

### EventBridge Pipes

AWS positions EventBridge Pipes as a point-to-point source-to-target integration with optional filtering and enrichment. That makes it a good fit for deterministic internal processing stages, such as:

- `tenant-events-queue` -> filter -> graph projector Lambda/ECS
- `graph-change-queue` -> controls evaluator
- `issue-change-queue` -> notification or ticket sink

Official sources:

- https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html
- https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-source.html
- https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-target.html

### SQS FIFO

AWS documents FIFO queues as preserving order and supporting deduplication/exactly-once behavior semantics appropriate for ordered workflows. That is the right default when graph changes for the same tenant/resource must be applied in order.

This is especially relevant for:

- `resource-exposed`
- `resource-patched`
- `trust-edge-added`
- `trust-edge-removed`
- `issue-opened`
- `issue-resolved`

Official sources:

- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-fifo-queues.html
- https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-exactly-once-processing.html

### EventBridge Bus vs Pipes

AWS distinguishes Pipes from event buses:

- **Pipes** are best for point-to-point flows
- **Event buses** are better for many-to-many routing

For Cloudforge, the clean split is:

- **Pipes** inside the core graph/issue pipeline
- **Event bus or SNS** when the same event needs to feed notifications, analytics, audit sinks, or external integrations

Official source:

- https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes.html

## Recommended Internal Event Envelope

```json
{
  "event_id": "uuid",
  "tenant_id": "tenant-123",
  "event_type": "finding.updated",
  "provider": "aws",
  "resource_id": "arn:aws:s3:::bucket-a",
  "account_id": "123456789012",
  "occurred_at": "2026-03-31T08:00:00Z",
  "trace_id": "uuid",
  "payload": {}
}
```

Required routing keys:

- `tenant_id`
- `event_type`
- `resource_id`
- `provider`
- `occurred_at`

These are enough to:

- preserve tenant isolation
- group ordered message streams by tenant/resource
- deduplicate retries
- trace issue lifecycles back to source changes

## Recommended Processing Topology

### Stage 1: Raw ingest

Producers emit raw deltas from:

- CSPM/adapters
- inventory sync
- identity sync
- runtime detections
- manual workflow state changes

### Stage 2: Normalize and enqueue

Write normalized events into a tenant-scoped queue model.

Recommended default:

- one logical FIFO queue per environment/service domain
- `MessageGroupId = tenant_id + ":" + resource_id`
- dedup ID derived from source event identity + version/timestamp

### Stage 3: Graph projector

Consumes normalized events and updates:

- graph vertices
- graph edges
- relational mirrors/search summaries where needed

If Neptune becomes the primary graph, this consumer is the canonical graph writer.

### Stage 4: Controls evaluator

Consumes graph-change events and evaluates only impacted controls, not the full corpus.

This is where incremental recomputation matters. For example:

- exposure edge changed -> reevaluate internet-exposure controls
- trust edge changed -> reevaluate identity path controls
- finding severity/CVE changed -> reevaluate vulnerability-based controls

### Stage 5: Issue materializer

Consumes control evaluation changes and applies:

- dedup
- issue open/update/resolve transitions
- risk rescoring
- blast radius / exposure path count refresh

### Stage 6: Downstream fanout

Only after issue change is stable:

- ticket creation/update
- Slack/email/webhook notifications
- analytics/search refresh
- UI push/SSE updates

## Tenant Isolation Guidance

The queueing model must isolate tenants operationally as well as logically.

Recommended minimum:

- every normalized event carries `tenant_id`
- consumers reject events missing `tenant_id`
- graph edges and issue rows store `tenant_id`
- cache keys include `tenant_id`
- notification and ticket sinks use tenant-scoped routing configuration

Recommended stronger posture:

- separate queues or message groups per tenant class
- per-tenant dead-letter visibility
- per-tenant backpressure/lag metrics

## Failure Model

### Use FIFO when:

- order changes meaningfully affect current graph state
- issue lifecycle should not flap due to reordering
- duplicate suppression is important

### Use standard queues when:

- workload is high-volume and order is irrelevant
- consumer logic is idempotent and merge-safe

### Dead-letter handling

Every stage should have its own DLQ so failures are attributable:

- normalization DLQ
- graph projector DLQ
- controls evaluator DLQ
- issue materializer DLQ

Do not collapse all failures into one shared DLQ; that obscures where graph state drift begins.

## Implementation Guidance for Cloudforge

### Near term

- Keep this as an architecture contract first.
- Add event envelope types and idempotency helpers before wiring external AWS services.
- Build the graph projector and issue materializer as internal interfaces so deployment topology can evolve later.

### Medium term

- If Neptune is chosen as the primary graph, add a graph-change emission model after projector writes.
- Evaluate Neptune Streams only after Neptune owns the authoritative graph state.

### Guardrail

Do not bind the application contract too tightly to a single AWS transport primitive. Keep these abstractions stable:

- normalized event
- graph projector
- controls evaluator
- issue materializer
- notifier

The transport can be SQS/Pipes/EventBridge today and changed later without rewriting the domain model.

## Recommended Decision

- `WSG-3 status:` architecture decision complete
- `Recommended baseline:` SQS + EventBridge Pipes for the internal pipeline
- `Recommended fanout pattern:` SNS or EventBridge bus for many-to-many downstream reactions
- `Recommended ordering rule:` FIFO for tenant/resource-sensitive graph mutation streams
- `Recommended next implementation step:` add internal event envelope and projector/evaluator/materializer interfaces before external infra wiring
