# CloudForge Portal

Self-service cloud governance portal — React 19 + Vite 7 + Tailwind CSS v4 + shadcn/ui.

**Live:** [cloudforge.lvonguyen.com](https://cloudforge.lvonguyen.com)

---

## Quick Start

```bash
npm install
npm run dev       # http://localhost:5173
npm run build     # Production build
npm run deploy    # Deploy to Cloudflare Pages
```

## Structure

```text
src/
├── pages/
│   ├── admin/       # Policy manager, AI agents, users, audit log, system health
│   ├── ops/         # Command center, findings, remediation queue, costs, compliance
│   └── portal/      # Request wizard, catalog, request tracking
├── components/
│   ├── ui/          # shadcn/ui primitives (button, card, table, dialog, etc.)
│   ├── layout/      # AppShell, TopNav, Sidebar
│   └── portal/      # DeployPreview, TerminalOutput
├── hooks/           # API/data hooks, UI helpers, terminal and SSE clients
├── lib/             # API client, auth context, utilities
└── types/           # Deploy types, shared interfaces
```

## Auth Model

- `DEV`: bypasses auth with a local preview role switcher.
- `VITE_DEMO_MODE=true`: enables demo/static auth and mock fallbacks for the public portfolio deployment.
- `VITE_OKTA_ISSUER` + `VITE_OKTA_CLIENT_ID`: enable the browser-owned Okta SPA PKCE flow that returns to `/callback`.
- The frontend does not use a backend BFF or cookie session layer today.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_API_URL` | `/api/v1` | API base URL |
| `VITE_DEMO_MODE` | *(empty)* | Enables demo auth + mock-friendly behavior |
| `VITE_ENABLE_MOCK_FALLBACK` | *(empty)* | Allows hooks to fall back to local mock data outside full demo mode |
| `VITE_OKTA_ISSUER` | *(empty)* | Okta issuer for SPA PKCE |
| `VITE_OKTA_CLIENT_ID` | *(empty)* | Okta SPA client ID |
| `VITE_STATIC_TOKEN` | *(empty)* | Pre-signed JWT embedded at build time |
| `VITE_DEV_TOKEN` | *(empty)* | Dev-only bearer token override |
| `VITE_WS_URL` | *(empty)* | SSE/WebSocket server URL |
| `VITE_COMPANY_NAME` | `Contoso` | Branding company name |
| `VITE_PRODUCT_NAME` | `CloudForge` | Branding product name |
| `VITE_LOGO_PATH` | `/icons/aegis-logo.svg` | Logo path; legacy asset filename is still in use |
| `VITE_EMAIL_DOMAIN` | `contoso.dev` | Demo email domain |
| `VITE_REPO_PREFIX` | `github.com/contoso` | Repo URL prefix shown in UI |
| `VITE_ENABLED_MODULES` | `cloudforge,posture-management,threat-intel,remediation-engine,ops-center` | Feature/module labels |
| `VITE_STORAGE_PREFIX` | `aegis` | Storage namespace prefix retained for compatibility |
| `VITE_BRAND_PRIMARY` | *(empty)* | Primary theme color |
| `VITE_BRAND_SECONDARY` | *(empty)* | Secondary theme color |
| `VITE_BRAND_ACCENT` | *(empty)* | Accent theme color |
| `VITE_THEME` | `neutral` | Default theme preset |
| `VITE_DEMO_ACCESS_ENABLED` | *(empty)* | Shows demo-access affordances on the landing page |
| `VITE_DEMO_VIEWER_EMAIL` | *(empty)* | Demo login email hint |
| `VITE_DEMO_VIEWER_PASSWORD` | *(empty)* | Demo password hint/content source |

## Hook Inventory

The `src/hooks/` layer currently exposes 27 hooks:

- `useActionCooldown`
- `useAgents`
- `useASM`
- `useAttackPathAnalysis`
- `useAttackPaths`
- `useAuditLog`
- `useCatalog`
- `useChannel`
- `useComments`
- `useCompliance`
- `useCompliancePosture`
- `useCosts`
- `useDebounce`
- `useDeployPreview`
- `useExceptions`
- `useFindings`
- `useGraphQuery`
- `useIntegrations`
- `useIssues`
- `useMediaQuery`
- `useOrgScan`
- `usePolicies`
- `useRemediations`
- `useTerminalWS`
- `useToast`
- `useUsers`
- `useWebhooks`

## Design System

- Warm grays + amber accent (#F5D288), industrial aesthetic
- Inter (body) + JetBrains Mono (headings/mono)
- No rounded corners — sharp edges everywhere
- Dark mode via CSS variable overrides on `.dark` class

## Deploy

Hosted on Cloudflare Pages (`cloudforge-demo` project, custom domain `cloudforge.lvonguyen.com`).

```bash
npm run deploy    # Uses wrangler@latest
```
