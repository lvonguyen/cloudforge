# Whitelabel Exploration — Cloud Aegis Platform

> Design document for multi-tenant branding and white-label deployment support.

---

## 1. Current Hardcoded Branding Inventory

### Company Name: "Contoso"

| Location | Count | Type |
|----------|-------|------|
| `frontend/src/lib/auth.ts` | 1 | Default user email (`admin1@contoso.dev`) |
| `frontend/src/lib/mock/*.json` | ~100+ | Mock data emails (audit-log, agents, users, traces) |
| `frontend/src/pages/ops/CommandCenter.tsx` | 8 | Mock exception emails |
| `frontend/src/pages/ops/FindingDetail.tsx` | 1 | Default requestor email |
| `frontend/src/pages/admin/PolicyDetail.tsx` | 25+ | Mock violation data, Rego policy snippets |
| `frontend/src/pages/portal/*.tsx` | 30+ | Mock request/approval emails |
| `frontend/src/components/grc/__tests__/*.tsx` | 10+ | Test fixture emails |
| `frontend/src/hooks/__tests__/*.ts` | 10+ | Test fixture emails |

### Product Name: "CloudForge"

| Location | Type |
|----------|------|
| `frontend/src/components/layout/TopNav.tsx:36` | Header bar product name |
| `frontend/src/pages/Landing.tsx:83` | H1 heading ("CloudForge Platform") |
| `frontend/src/pages/Landing.tsx:26,32,80` | Project card name, logo path |
| `frontend/src/pages/admin/AIAgentDetail.tsx:35` | STRIDE description text |
| `frontend/src/lib/auth.ts:26-28` | localStorage keys (`cloudforge_role`, etc.) |
| `frontend/src/lib/plan-templates.ts:102` | Security group description |
| `frontend/index.html:8` | `<title>` tag |

### Logo References

| Location | Path |
|----------|------|
| `frontend/src/pages/Landing.tsx:32,80` | `/icons/cloudforge-logo.svg` |
| `frontend/src/components/layout/TopNav.tsx:31-35` | Inline SVG shield icon |
| `frontend/index.html:5` | `/logo.svg` favicon |

---

## 2. Phase 1 Parameterization Strategy (Implemented)

### Vite Environment Variables

```bash
# .env.development / .env.example
VITE_COMPANY_NAME=Contoso
VITE_PRODUCT_NAME=CloudForge
VITE_LOGO_PATH=/icons/cloudforge-logo.svg
VITE_EMAIL_DOMAIN=contoso.dev
```

### Centralized Branding Config

```typescript
// frontend/src/lib/branding.ts
export const branding = {
  companyName: import.meta.env.VITE_COMPANY_NAME || 'Contoso',
  productName: import.meta.env.VITE_PRODUCT_NAME || 'CloudForge',
  logoPath:    import.meta.env.VITE_LOGO_PATH || '/icons/cloudforge-logo.svg',
  emailDomain: import.meta.env.VITE_EMAIL_DOMAIN || 'contoso.dev',
}
```

### Phase 1 Scope (Current Sprint)

Components updated to read from `branding`:
- **TopNav** — product name in header
- **Landing page** — H1 heading, project card repo prefix
- **Auth defaults** — default user email domain

Components **not** updated (Phase 2):
- Mock JSON data files (audit-log, users, agents, traces)
- PolicyDetail Rego snippets (hardcoded `ecr.contoso.dev`)
- `index.html` title tag (requires build-time interpolation or Vite plugin)
- localStorage key prefixes (`cloudforge_*`)

---

## 3. Multi-Tenant Architecture Considerations

### Option A: Per-Tenant Builds (Recommended for Phase 2)

```
.env.contoso       → VITE_COMPANY_NAME=Contoso
.env.haea          → VITE_COMPANY_NAME=HAEA
.env.acme          → VITE_COMPANY_NAME=Acme Corp

# Build command:
vite build --mode contoso
vite build --mode haea
```

**Pros:** Zero runtime cost, tree-shakes unused branding, each deploy is a static bundle.
**Cons:** Requires separate build + deploy per tenant. N tenants = N Cloudflare Pages projects.

### Option B: Runtime Config (Phase 3+)

Serve a `/config.json` at runtime that the SPA fetches on startup:

```json
{
  "companyName": "HAEA",
  "productName": "SecureCloud",
  "logoPath": "/branding/haea-logo.svg",
  "emailDomain": "haea.io",
  "modules": ["cloudforge", "cspm-aggregator"]
}
```

**Pros:** Single build artifact, config changes without redeploy.
**Cons:** FOUC (flash of unstyled content) during config fetch, runtime overhead, harder to tree-shake.

### Option C: Full Multi-Tenant (Phase 4+)

Single deployment serving multiple tenants via subdomain routing:

```
contoso.cloudforge.io  → tenant=contoso
haea.cloudforge.io     → tenant=haea
```

Backend scopes all data queries to `tenant_id`. Auth middleware extracts tenant from subdomain or JWT claim.

**Pros:** Single infrastructure, shared codebase, centralized management.
**Cons:** Significant backend work — tenant-scoped database, auth provider per tenant, data isolation.

---

## 4. Config-Driven Module Visibility

The Landing page PROJECTS array can be controlled per tenant:

```typescript
// branding.ts
export const branding = {
  // ...
  enabledModules: (import.meta.env.VITE_ENABLED_MODULES || 'cloudforge,cspm-aggregator')
    .split(','),
}

// Landing.tsx
const visible = PROJECTS.filter(p => branding.enabledModules.includes(p.slug))
```

This allows tenants to show/hide modules without code changes.

---

## 5. Backend Considerations

### Tenant-Scoped Data (Phase 3+)
- Add `tenant_id` column to all database tables
- JWT claims include `tenant_id` field
- All queries filter by `tenant_id` from auth context
- GRC provider supports multi-tenant data isolation

### Auth Provider Per Tenant
- Each tenant configures their own OIDC provider (Okta, Entra ID, Auth0)
- Tenant config maps subdomain → OIDC issuer
- JWKS caching is per-issuer

### API Rate Limiting
- Rate limits can be per-tenant, not just per-user
- Enterprise tenants get higher limits

---

## 6. Effort Estimates

| Phase | Scope | Effort |
|-------|-------|--------|
| Phase 1 (done) | Env var branding, centralized config, key component updates | 1 day |
| Phase 2 | Per-tenant builds, mock data parameterization, full component sweep | 2-3 days |
| Phase 3 | Runtime config, module visibility, backend tenant scaffolding | 1-2 weeks |
| Phase 4 | Full multi-tenant (DB scoping, per-tenant auth, data isolation) | 3-4 weeks |

---

## 7. Recommended Path Forward

1. **Now:** Ship Phase 1 (env vars + branding.ts). This unblocks demo customization.
2. **Next sprint:** Phase 2 per-tenant builds for HAEA. Create `.env.haea` with HAEA branding and deploy to `haea-demo.lvonguyen.com`.
3. **When needed:** Phase 3 runtime config if the number of tenants grows beyond 3-4.
4. **Production:** Phase 4 full multi-tenant only when there's a real commercial need.
