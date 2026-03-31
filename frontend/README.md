# Cloud Aegis Portal

Self-service cloud governance portal — React 19 + Vite 7 + Tailwind CSS v4 + shadcn/ui.

**Live:** [cloudaegis-demo.lvonguyen.com](https://cloudaegis-demo.lvonguyen.com)

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
├── hooks/           # useDeployPreview
├── lib/             # API client, auth context, utilities
└── types/           # Deploy types, shared interfaces
```

## Design System

- Warm grays + amber accent (#F5D288), industrial aesthetic
- Inter (body) + JetBrains Mono (headings/mono)
- No rounded corners — sharp edges everywhere
- Dark mode via CSS variable overrides on `.dark` class

## Deploy

Hosted on Cloudflare Pages (`cloudforge-demo` project, custom domain `cloudaegis-demo.lvonguyen.com`).

```bash
npm run deploy    # Uses wrangler@latest
```
