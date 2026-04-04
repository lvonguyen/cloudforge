# ADR-012: Whitelabel/Multi-Tenant Architecture

## Status

Accepted

## Date

2026-03-12

## Context

CloudForge needs to support whitelabel deployment for MSP (Managed Security Provider) customers who resell the platform under their own brand. This requires configurable branding without forking the codebase.

The platform already has:
- A React 19 SPA deployed to Cloudflare Pages
- A centralized branding config at `frontend/src/lib/branding.ts`
- Environment variable support via Vite's `import.meta.env`

### Requirements

- Company name, product name, and tagline configurable without code changes
- Logo, favicon, and color scheme customizable per deployment
- Support for multiple deployment instances with different branding
- No runtime performance impact from branding configuration

## Decision

A **4-phase whitelabel strategy** was selected, starting with environment variable-driven branding and progressing to full multi-tenant support.

### Phase 1: Environment Variable Branding (Done)

All branding values are read from environment variables at build time:

```typescript
// frontend/src/lib/branding.ts
export const branding = {
  companyName: import.meta.env.VITE_COMPANY_NAME || 'CloudForge',
  productName: import.meta.env.VITE_PRODUCT_NAME || 'CloudForge',
  tagline: import.meta.env.VITE_TAGLINE || 'Enterprise Cloud Governance',
  // ...
}
```

Variables documented in `.env.example`. Each Cloudflare Pages deployment sets its own values.

### Phase 2: Theme Configuration (Done)

CSS custom properties for colors, typography, and spacing. `VITE_BRAND_PRIMARY`, `VITE_BRAND_SECONDARY`, `VITE_BRAND_ACCENT`, and `VITE_THEME` are implemented in `frontend/src/lib/branding.ts` and applied via CSS variable overrides at build time.

### Phase 3: Logo/Asset Pipeline (Partial)

`VITE_LOGO_PATH` is configurable for logo override. Per-tenant asset directory with automated favicon/OG image selection is not yet built.

### Phase 4: Runtime Multi-Tenant (Planned)

Tenant ID in JWT claims. Backend serves tenant-specific configuration. Database row-level security for data isolation.

## Consequences

### Positive

- **Zero-fork branding**: MSPs customize without maintaining a fork
- **Build-time optimization**: No runtime overhead for branding lookups
- **Progressive complexity**: Phase 1 is simple env vars; later phases add sophistication as needed

### Negative

- **Build-per-tenant**: Phase 1-3 require a separate build per branded deployment
- **No runtime switching**: Cannot change branding without rebuild (until Phase 4)

### Mitigations

- Cloudflare Pages supports multiple deployments from the same repo with different env vars
- Phase 4 (runtime) eliminates the build-per-tenant limitation

## References

- `frontend/src/lib/branding.ts` — Centralized branding configuration
- `docs/whitelabel-exploration.md` — Full 4-phase design document
- `.env.example` — Branding environment variable documentation
