# Blocked Items

## Neon Postgres Setup

**Status:** BLOCKED — `neonctl` not available on this machine.

### Manual Steps (Neon Dashboard)

1. Go to [console.neon.tech](https://console.neon.tech)
2. Create project: `cloudforge-prod` (or `cloudforge-dev` for dev)
3. Default database: `cloudforge`, role: `cloudforge_app`
4. Copy connection string from the dashboard

### Fly.io Deployment

```bash
# Extract connection string from Neon dashboard, then:
fly secrets set DATABASE_URL="postgres://cloudforge_app:PASSWORD@ep-XXXX.REGION.aws.neon.tech/cloudforge?sslmode=require"
```

### Local Development

Local dev continues using the in-memory provider (no change needed).
`docker-compose.yml` already reads `DATABASE_URL` env var — set it to
a local Postgres instance if you want to test with a real database.

### Code Notes

- `internal/grc.NewProvider(cfg)` already supports `postgres` type and reads `DATABASE_URL`
- No application code changes required — only infrastructure provisioning
