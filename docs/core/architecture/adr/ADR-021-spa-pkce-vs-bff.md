# ADR-021: Frontend Auth Model - Keep SPA PKCE, Defer BFF

## Status

Accepted

## Date

2026-04-03

## Context

CloudForge already has a working frontend-owned Okta login flow:
- the SPA redirects users to the IdP with PKCE
- the SPA handles the `/callback` route
- the SPA exchanges the authorization code directly with the IdP token endpoint
- the backend API validates bearer JWTs via HS256 or RS256/JWKS and applies RBAC

The repo previously implied a missing backend OAuth callback implementation under `internal/api`. That framing was misleading in the current deployment model:
- frontend is hosted on Cloudflare Pages
- API is hosted separately on Fly.io
- no backend session store exists
- no `httpOnly` cookie flow exists
- no refresh-token ownership or rotation lifecycle exists on the server

The real decision is not "should we add a callback handler." The decision is whether CloudForge should keep the current SPA PKCE model or invest in a real Backend-for-Frontend (BFF) session architecture.

## Decision Drivers

- Keep the deployed auth model aligned with the actual hosting topology
- Avoid duplicate auth plumbing that adds complexity without improving security posture
- Make documentation honest about what exists today
- Preserve a clean path to a future BFF if requirements change

## Options Considered

### Option A: Keep SPA PKCE

Characteristics:
- browser owns the PKCE verifier and callback flow
- API only validates bearer JWTs
- demo deployments can continue using static/demo auth modes
- no backend session store required

Pros:
- matches the current Cloudflare Pages plus Fly.io split
- already implemented and verified in the frontend
- lowest operational complexity
- no CSRF or cookie session layer to maintain

Cons:
- access tokens live in browser-managed storage
- logout semantics stay IdP plus client-session oriented
- server cannot centrally own refresh-token lifecycle

### Option B: Introduce a Real BFF

Characteristics:
- backend owns authorize/callback flows
- backend stores or brokers session state
- frontend uses `httpOnly` cookies instead of directly handling access tokens

Pros:
- stronger token handling boundary
- cleaner server-owned session lifecycle
- enables centralized logout, refresh rotation, and tighter policy controls

Cons:
- materially more implementation work
- requires CSRF protection, session storage, logout design, cookie strategy, and operational hardening
- does not fit as a small follow-up patch

## Decision

CloudForge will keep the current SPA PKCE model for the active deployment and documentation baseline.

The team will not add backend authorize/callback routes unless there is an explicit decision to adopt a full BFF/session architecture. Any future BFF work must include:
- `httpOnly` cookie strategy
- CSRF protection
- refresh-token ownership and rotation
- logout semantics
- session storage and lifecycle management

## Consequences

### Positive

- Documentation now matches the code and the deployment model
- Auth work stays proportional to current needs
- Session B no longer carries a misleading "missing backend callback" item

### Negative

- Browser-managed token storage remains part of the current design
- Some enterprise auth requirements may eventually justify a BFF

## Triggers To Revisit

Reopen this decision if any of the following become requirements:
- refresh-token rotation managed by the server
- centralized logout and server-side session revocation
- stronger browser token exposure reduction via cookies
- multiple IdPs with server-owned federation logic
- compliance requirements that prohibit the current SPA token handling model

## Related Decisions

- [ADR-006](ADR-006-authentication.md): Authentication and Authorization
