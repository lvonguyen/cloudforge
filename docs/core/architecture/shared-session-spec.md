# Shared Session — E2E Design Spec

**Version:** 1.0
**Author:** Liem Vo-Nguyen
**Date:** March 2026
**Status:** Draft

---

## 1. Problem Statement

Three projects need real-time event streaming with overlapping requirements but no shared infrastructure:

| Project | Current Implementation | Pain Point |
|---------|----------------------|------------|
| **CloudForge** | `useDeployPreview` — client-side `setTimeout` simulation | No real backend stream; ExecutionTracePanel can't show live remediation or agent trace data |
| **lvn-clopusgotchi** | `StreamServer` (TS) + `SyncMCPClient` (TS→Go) | Two independent SSE paths with independent reconnection chains; 100+ LOC manual SSE parser; cold-start stale window |
| **Stellar AIO** | Not yet built | Needs broadcast-by-topic for real-time collaboration |

Each project has built (or will build) its own connection management, heartbeat, auth, backpressure handling, and reconnection logic. This spec defines a shared session layer that all three can consume.

---

## 2. Consumers & Their Needs

### 2.1 CloudForge — Execution Trace Streaming

**Current state:** `TracePanelProvider` (React context) drives `ExecutionTracePanel` with three modes:
- `streaming` — fed by `useDeployPreview` which simulates events via `setTimeout`
- `timeline` — static `Span[]` data
- `dry-run` — static `DryRunResult` data

**Target state:** Replace `useDeployPreview` simulation with real SSE/WS events from the Go backend. The `appendEvent` dispatch already accepts `DeployEvent` — the only missing piece is a real event source.

**Required channels:**
| Channel | Direction | Events |
|---------|-----------|--------|
| `deploy:{executionId}` | Server→Client (SSE) | `planning`, `creating`, `configuring`, `verifying`, `live`, `teardown`, `complete` |
| `trace:{agentId}` | Server→Client (SSE) | Agent execution spans, tool calls, decisions |
| `remediation:{findingId}` | Server→Client (SSE) | Dry-run progress, apply progress, rollback events |

**Blockers (must fix first):**
1. **D12 — gzipResponseWriter** in `cmd/server/middleware.go` needs `Flush()` and `Hijack()` methods. Without these, SSE and WS upgrades fail when gzip middleware is active.
2. **Terminal token endpoint** — `POST /api/terminal/token` not yet implemented.

### 2.2 lvn-clopusgotchi — Bidirectional Session Sync

**Current state:** Two distinct SSE paths exist:

| Path | Direction | Implementation | LOC |
|------|-----------|----------------|-----|
| **Outbound** (daemon→web/iOS) | Server→Client | `StreamServer` (TypeScript) — 10 client cap, backpressure detection, 30s heartbeat, 4hr max connection | ~250 |
| **Inbound** (sync-mcp→daemon) | Server→Client | `SyncMCPClient` (TypeScript→Go) — hand-rolled line parser, 3-30s backoff, 1000-ID dedup set | ~150 |

**Cold-start reconnection chain (key pain point):**
```
launchd restart → daemon boots (~2s) → SyncMCPClient SSE backoff (3-30s)
→ sync-mcp (Go) may also restart → web/iOS re-poll (5-60s per hook)
```
Each hop has independent reconnection delay. During this window, all clients see stale data.

**wskit migration path:**

| Dimension | Current SSE | wskit WS |
|-----------|-------------|----------|
| daemon→web/iOS | `StreamServer` (TS) — stays as-is | No change (wskit is Go) |
| daemon↔sync-mcp | SSE push + REST calls (2 paths) | Single WS connection, bidirectional |
| Reconnect window | 3-30s exponential backoff | Sub-second with heartbeat keepalive |
| `SyncMCPClient` | 100+ LOC manual SSE parser + dedup | Eliminated — wskit handles framing |
| Channel isolation | Broadcast all events to all consumers | Rooms by repo/team |

**Target state:** Replace the inbound `SyncMCPClient` SSE path with a wskit WS connection. The outbound `StreamServer` stays as-is (it's TypeScript, wskit is Go, and it works well at current scale).

**Required channels:**
| Channel | Direction | Events |
|---------|-----------|--------|
| `sync:{repoPath}` | Bidirectional (WS) | `commit`, `decision`, `blocker`, `lock_acquired`, `lock_released` |
| `agent:{agentId}` | Server→Client | `agent_registered`, `agent_heartbeat`, `agent_deregistered` |
| `ci:{repoPath}` | Server→Client | `workflow_started`, `workflow_completed`, `workflow_failed` |

### 2.3 Stellar AIO — Collaboration Broadcast

**Target state (greenfield):**
| Channel | Direction | Events |
|---------|-----------|--------|
| `workspace:{workspaceId}` | Bidirectional (WS) | Cursor position, selection, presence |
| `build:{buildId}` | Server→Client (SSE) | Build progress, test results, deploy status |

---

## 3. Shared Session Architecture

### 3.1 wskit Package Layout

Follows the existing shared tools pattern (`sync-mcp`, `inference-mcp`):

```
shared/tools/ws-server/
  cmd/ws-server/
    main.go              # Standalone hub (optional — most consumers embed)
  pkg/wskit/
    server.go            # Hub + upgrader + connection lifecycle
    client.go            # Go WS client (for service-to-service)
    room.go              # Topic-based pub/sub (channel → subscribers)
    heartbeat.go         # Ping/pong + dead connection reaping
    auth.go              # Pluggable auth (JWT, ticket, API key)
    sse.go               # SSE transport (shares room model with WS)
    message.go           # Envelope: {channel, event, data, id, timestamp}
    options.go           # Functional options for Hub configuration
  internal/stellar/
    handler.go           # First concrete consumer (Stellar AIO)
    models.go
  go.mod
  go.sum
  Makefile
  README.md
```

### 3.2 Core Abstractions

```go
// Hub manages all connections and rooms
type Hub struct {
    rooms      map[string]*Room
    register   chan *Conn
    unregister chan *Conn
    broadcast  chan *Envelope
    opts       Options
}

// Room is a named pub/sub channel
type Room struct {
    Name        string
    subscribers map[*Conn]struct{}
    history     []Envelope  // optional replay buffer
}

// Conn wraps a single client connection (WS or SSE)
type Conn struct {
    ID        string
    Transport Transport  // WS or SSE
    Rooms     map[string]struct{}
    UserID    string     // from auth
    send      chan []byte
    hub       *Hub
}

// Transport abstracts WS vs SSE
type Transport interface {
    Write(ctx context.Context, data []byte) error
    Close() error
    Type() string  // "ws" or "sse"
}

// Envelope is the wire format
type Envelope struct {
    Channel   string          `json:"channel"`
    Event     string          `json:"event"`
    Data      json.RawMessage `json:"data"`
    ID        string          `json:"id"`
    Timestamp time.Time       `json:"ts"`
}

// Authenticator validates connection credentials
type Authenticator interface {
    Authenticate(r *http.Request) (userID string, err error)
}
```

### 3.3 Auth Strategies

| Strategy | Use Case | Implementation |
|----------|----------|----------------|
| **JWT Bearer** | CloudForge API, Stellar | `Authorization: Bearer <token>` header on WS upgrade |
| **Ticket** | Clopusgotchi (EventSource can't set headers) | `POST /api/session/ticket` → 60s nonce → `?ticket=<nonce>` on connect |
| **API Key** | Service-to-service (sync-mcp↔daemon) | `?token=<key>` query param |
| **None** | Development / localhost | Configurable bypass |

```go
// Composable auth — try strategies in order
func ChainAuth(strategies ...Authenticator) Authenticator
```

### 3.4 Connection Lifecycle

```
Client                          Hub                           Room
  |                              |                              |
  |-- WS upgrade / SSE GET ----->|                              |
  |                              |-- Authenticate() ---------->|
  |                              |<- userID / error ------------|
  |                              |                              |
  |<---- connection accepted ----|                              |
  |                              |-- register(conn) ---------->|
  |                              |                              |
  |-- subscribe("deploy:x1") -->|                              |
  |                              |-- room.Add(conn) ---------->|
  |                              |<- history replay ------------|
  |<---- replay events ---------|                              |
  |                              |                              |
  |                    ... heartbeat ping/pong ...              |
  |                              |                              |
  |<---- event push ------------|<- broadcast(envelope) -------|
  |                              |                              |
  |-- unsubscribe / close ----->|                              |
  |                              |-- room.Remove(conn) ------->|
  |                              |-- unregister(conn) -------->|
```

### 3.5 SSE Transport

SSE uses the same `Room` model as WS but over `text/event-stream`. This is CloudForge's most practical first integration — `ExecutionTracePanel` already consumes a stream of `DeployEvent` objects, and SSE maps directly to `EventSource` in the browser.

```go
// SSE handler — shares rooms with WS connections
func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
    // 1. Authenticate
    // 2. Check Flusher interface (D12 fix required)
    // 3. Set headers: Content-Type: text/event-stream, Cache-Control: no-cache
    // 4. Create SSE Conn, register with hub
    // 5. Write loop: format Envelope → "event: {event}\ndata: {json}\nid: {id}\n\n"
    // 6. Heartbeat: ": keepalive\n\n" every 30s
}
```

**D12 prerequisite:** `gzipResponseWriter` in CloudForge's middleware.go must implement:
```go
func (w *gzipResponseWriter) Flush() {
    if f, ok := w.Writer.(http.Flusher); ok { f.Flush() }
}

func (w *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
    if h, ok := w.ResponseWriter.(http.Hijacker); ok { return h.Hijack() }
    return nil, nil, fmt.Errorf("hijack not supported")
}
```

### 3.6 Heartbeat & Dead Connection Reaping

```go
type HeartbeatConfig struct {
    PingInterval time.Duration // default: 30s
    PongTimeout  time.Duration // default: 10s
    MaxMissed    int           // default: 3 (reap after 3 missed pongs)
}
```

For WS: standard ping/pong frames.
For SSE: periodic `: keepalive\n\n` comment lines (client-side `EventSource` auto-reconnects on silence).

### 3.7 Backpressure

Borrowed from clopusgotchi's `StreamServer` (proven in production):

```go
const maxBackpressure = 5

func (c *Conn) write(data []byte) {
    select {
    case c.send <- data:
        c.backpressure = 0
    default:
        c.backpressure++
        if c.backpressure >= maxBackpressure {
            c.hub.unregister <- c  // evict slow client
        }
    }
}
```

---

## 4. Integration Plan by Consumer

### 4.1 CloudForge (highest value — unblocks ExecutionTracePanel)

**Phase 1: SSE endpoint (no wskit dependency)**
1. Fix D12: add `Flush()` + `Hijack()` to `gzipResponseWriter`
2. Add `GET /api/v1/events/stream?channel=deploy:{id}` SSE endpoint in Go
3. Create `useEventStream(channel)` React hook — wraps `EventSource`, dispatches to `TracePanelProvider.appendEvent`
4. Replace `useDeployPreview` setTimeout chain with real SSE events

**Phase 2: wskit adoption**
1. Import `pkg/wskit` into CloudForge's `go.mod`
2. Replace hand-rolled SSE endpoint with `hub.ServeSSE()`
3. Add WS endpoint alongside SSE for bidirectional use cases (terminal, AI chat)

### 4.2 lvn-clopusgotchi (medium priority — eliminates SyncMCPClient)

**Phase 1: wskit WS hub in sync-mcp**
1. Add wskit `Hub` to sync-mcp's HTTP server (alongside existing SSE)
2. Expose `WS /api/ws` endpoint with room-based subscriptions
3. Migrate daemon's `SyncMCPClient` from SSE line-parser to wskit Go client

**Phase 2: Outbound consideration**
- `StreamServer` (TS, daemon→web/iOS) stays as-is — it's TypeScript, well-tested, right scale
- If iOS needs WS fallback (Safari SSE reconnect issues), add a TS WS server that shares the same event bus

**Cold-start improvement:**
```
Before: launchd → daemon (2s) → SSE backoff (3-30s) → sync-mcp restart → poll (5-60s)
After:  launchd → daemon (2s) → WS connect (<1s) → room replay (instant)
```
Room history replay eliminates the stale-data window entirely.

### 4.3 Stellar AIO (greenfield — first full wskit consumer)

1. `internal/stellar/handler.go` — register rooms for workspaces and builds
2. Presence: heartbeat-based (`last_seen` in room metadata)
3. Collaboration: cursor/selection via WS broadcast within workspace room

---

## 5. Wire Protocol

### 5.1 Client→Server (WS only — SSE is unidirectional)

```json
{"action": "subscribe",   "channel": "deploy:exec-001"}
{"action": "unsubscribe", "channel": "deploy:exec-001"}
{"action": "publish",     "channel": "deploy:exec-001", "event": "status", "data": {...}}
```

### 5.2 Server→Client (WS and SSE)

**WS:**
```json
{"channel": "deploy:exec-001", "event": "creating", "data": {"message": "Creating S3 bucket..."}, "id": "evt-042", "ts": "2026-03-17T10:00:00Z"}
```

**SSE:**
```
event: creating
data: {"channel":"deploy:exec-001","message":"Creating S3 bucket..."}
id: evt-042

```

### 5.3 Channel Naming Convention

```
{domain}:{scope}

deploy:{executionId}     — CloudForge deploy preview
trace:{agentId}          — CloudForge agent traces
remediation:{findingId}  — CloudForge remediation progress
sync:{repoPath}          — Clopusgotchi sync-mcp events
agent:{agentId}          — Clopusgotchi agent registry
ci:{repoPath}            — Clopusgotchi CI events
workspace:{workspaceId}  — Stellar collaboration
build:{buildId}          — Stellar build progress
```

---

## 6. Client SDK (TypeScript)

For React consumers, a thin hook wrapping `EventSource` / `WebSocket`:

```typescript
// useChannel("deploy:exec-001", { transport: "sse" })
function useChannel(channel: string, opts?: { transport?: "sse" | "ws" }): {
  events: Envelope[]
  status: "connecting" | "open" | "reconnecting" | "closed"
  publish: (event: string, data: unknown) => void  // WS only
}
```

**Implementation notes:**
- SSE: `new EventSource(url + "?channel=" + channel)` — auto-reconnect built-in
- WS: `new WebSocket(url)` + send `{action: "subscribe", channel}` — manual reconnect with exponential backoff (mirrors clopusgotchi's 2s→30s, max 8 retries)
- Session stability: store preferred transport in `sessionStorage` (same pattern as `useFindings` source pinning)

---

## 7. Dependency Graph

```
pkg/wskit (Go library, zero external deps beyond nhooyr.io/websocket)
    │
    ├── CloudForge cmd/server
    │     └── SSE endpoint → TracePanelProvider.appendEvent
    │
    ├── sync-mcp (shared/tools/sync-mcp)
    │     └── WS hub → replaces SSE /api/events endpoint
    │
    ├── lvn-clopusgotchi daemon (TypeScript — uses wskit via WS client)
    │     └── SyncMCPClient replaced by native WS to sync-mcp hub
    │
    └── Stellar AIO (internal/stellar)
          └── First full-featured consumer (rooms, presence, broadcast)
```

---

## 8. What NOT to Build (YAGNI)

| Feature | Reason to defer |
|---------|-----------------|
| `router.go` (JSON message dispatcher) | Stellar uses broadcast, CloudForge SSE is unidirectional — no routing needed yet |
| Message persistence / replay beyond in-memory ring buffer | sync-mcp has SQLite for durable events; wskit handles ephemeral streams |
| Multi-node hub (Redis pub/sub) | All consumers are single-instance today |
| Binary protocol (protobuf/msgpack) | JSON is fine at current event volumes (<100/s) |
| Rate limiting per channel | Backpressure eviction is sufficient |

---

## 9. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | wskit `Hub` starts, accepts WS + SSE connections | Unit test: 2 clients subscribe to same room, both receive broadcast |
| 2 | Room history replay on connect | Unit test: publish 5 events, new client connects, receives all 5 |
| 3 | Heartbeat reaps dead connections | Unit test: client stops responding to pings, reaped after `MaxMissed` |
| 4 | Backpressure evicts slow clients | Unit test: slow consumer evicted after 5 buffer-full signals |
| 5 | JWT + Ticket auth both work | Integration test: valid/invalid tokens, expired tickets |
| 6 | CloudForge SSE endpoint streams deploy events | E2E: trigger deploy preview, verify `EventSource` receives events in order |
| 7 | D12 gzip fix doesn't break existing responses | Regression: all existing API tests pass with gzip enabled |
| 8 | Clopusgotchi WS replaces SyncMCPClient SSE | Integration: daemon connects to sync-mcp via WS, receives events without manual parsing |
| 9 | Cold-start reconnect < 3s (was 3-60s) | Timed test: restart sync-mcp, measure time until daemon receives first event |

---

## 10. Sequencing

| Phase | Work | Depends On | Consumer |
|-------|------|------------|----------|
| **0** | Fix D12 (`gzipResponseWriter` Flush/Hijack) | — | CloudForge |
| **1** | `pkg/wskit/server.go` + `room.go` + `heartbeat.go` + `auth.go` | — | All |
| **2** | `pkg/wskit/sse.go` | Phase 1 | CloudForge |
| **3** | CloudForge SSE endpoint + `useChannel` hook | Phase 0 + 2 | CloudForge |
| **4** | `pkg/wskit/client.go` | Phase 1 | Clopusgotchi |
| **5** | sync-mcp WS hub + daemon migration | Phase 4 | Clopusgotchi |
| **6** | `internal/stellar/handler.go` | Phase 1 | Stellar |
| **7** | `pkg/wskit/message.go` (envelope, serialization) | Phase 1 | All |

Phases 0-2 are CloudForge-critical. Phases 4-5 are medium priority (do when sync-mcp gets its next touch). Phase 6 is greenfield (Stellar timeline).

---

## Related Documents

| Document | Description |
|----------|-------------|
| [Terminal VPS Brief](./terminal-vps-brief.md) | WS terminal server on shared VPS (Node.js, port 8088) |
| [HLD](./HLD.md) | CloudForge high-level architecture |
| [ADR-014](adr/ADR-014-event-driven-ingestion.md) | Event-driven ingestion (Accepted) |
| sync-mcp README | Go MCP server with SSE event bus |
