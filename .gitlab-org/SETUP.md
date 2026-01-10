# GitLab CI/CD Setup for Portfolio

This directory contains CI/CD templates for GitLab repositories.

---

## [>] Quick Setup

```bash
# Copy templates to your GitLab shared location
cp -r ci-templates/* ~/repos/remote/gl/lvonguyen/lvonguyen-group/portfolio/shared/ci-templates/

# Commit and push
cd ~/repos/remote/gl/lvonguyen/lvonguyen-group/portfolio/shared
git add ci-templates/
git commit -m "feat: Add shared CI/CD templates for portfolio"
git push
```

---

## [/] Directory Structure

```
portfolio/shared/
├── ci-templates/
│   ├── go-ci.yml          # Go build, test, lint
│   ├── python-ci.yml      # Python with uv, pytest, ruff
│   └── terraform-ci.yml   # Terraform validate, security scan
└── standards/
    ├── DEV_GUIDE.md
    ├── REPO_ORGANIZATION.md
    └── ...
```

---

## [+] Using Templates in Repos

### Option A: Include from Remote (Recommended)

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/go-ci.yml'
```

### Option B: Include from URL

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://gitlab.com/lvonguyen/lvonguyen-group/portfolio/shared/-/raw/main/ci-templates/go-ci.yml'
```

### Option C: Override Variables

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/go-ci.yml'

variables:
  GO_VERSION: "1.23"  # Override default
```

### Option D: Extend Jobs

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/python-ci.yml'

# Add custom job
security-scan:
  stage: test
  script:
    - uv run bandit -r src/
```

---

## [/] Template Reference

### go-ci.yml

| Job | Stage | Description |
|-----|-------|-------------|
| `build` | build | `go build ./...` |
| `test` | test | `go test -race -cover` |
| `lint` | lint | `golangci-lint run` |
| `opa-test` | test | OPA policy tests (if policies/ exists) |

**Variables:**
- `GO_VERSION` - Default: `1.24`
- `GOLANGCI_LINT_VERSION` - Default: `v1.62.0`

### python-ci.yml

| Job | Stage | Description |
|-----|-------|-------------|
| `build` | build | Install deps with `uv sync` |
| `test` | test | `pytest` with coverage |
| `lint` | lint | `ruff check` + `ruff format` |
| `typecheck` | lint | `mypy` (optional, allow_failure) |

**Variables:**
- `PYTHON_VERSION` - Default: `3.12`

### terraform-ci.yml

| Job | Stage | Description |
|-----|-------|-------------|
| `fmt` | validate | `terraform fmt -check` |
| `validate` | validate | `terraform validate` |
| `tfsec` | security | Security scanning |
| `checkov` | security | Policy-as-code scanning |
| `plan` | plan | `terraform plan` (manual trigger) |

**Variables:**
- `TF_VERSION` - Default: `1.9.0`
- `TF_ROOT` - Default: `infra` |

---

## [!] GitLab Group Settings

Go to: **gitlab.com/groups/lvonguyen/lvonguyen-group/-/settings/ci_cd**

### General CI/CD Settings

1. **Auto DevOps:** Disabled (using custom templates)
2. **Shared runners:** Enabled
3. **Git shallow clone:** 50 (faster clones)

### Protected Branches (per repo)

**Settings -> Repository -> Protected branches**

| Branch | Allowed to merge | Allowed to push |
|--------|------------------|-----------------|
| `main` | Maintainers | No one |

### Merge Request Settings

**Settings -> Merge requests**

- [x] Pipelines must succeed
- [x] All threads must be resolved
- [x] Squash commits (optional)
- [ ] Delete source branch (optional)

---

## [>] Group-Level CI/CD Variables

**Settings -> CI/CD -> Variables**

Add secrets that all repos can use:

| Variable | Protected | Masked | Description |
|----------|-----------|--------|-------------|
| `SONAR_TOKEN` | Yes | Yes | SonarQube access |
| `AWS_ACCESS_KEY_ID` | Yes | Yes | AWS (read-only) |
| `AWS_SECRET_ACCESS_KEY` | Yes | Yes | AWS secret |

---

## [+] Comparison: GitHub vs GitLab

| Feature | GitHub Actions | GitLab CI |
|---------|---------------|-----------|
| Config file | `.github/workflows/*.yml` | `.gitlab-ci.yml` |
| Reuse | `uses:` / `workflow_call` | `include:` / `extends:` |
| Caching | `actions/cache@v4` | `cache:` keyword |
| Artifacts | `actions/upload-artifact` | `artifacts:` keyword |
| Variables | `${{ vars.NAME }}` | `${NAME}` |
| Secrets | `${{ secrets.NAME }}` | `${NAME}` (CI variable) |
| Manual jobs | `workflow_dispatch` | `when: manual` |
| Conditional | `if:` | `rules:` |

---

## [/] Sample Repo Configuration

### Go Project (e.g., cloudforge)

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/go-ci.yml'

# All jobs from go-ci.yml are included automatically
```

### Python Project (e.g., cspm-aggregator)

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/python-ci.yml'

variables:
  PYTHON_VERSION: "3.11"  # Override if needed
```

### Multi-Language Project

```yaml
# .gitlab-ci.yml
include:
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/python-ci.yml'
  - project: 'lvonguyen/lvonguyen-group/portfolio/shared'
    ref: main
    file: '/ci-templates/terraform-ci.yml'

variables:
  TF_ROOT: "infra/aws"
```

---

## [!] Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `include not found` | Wrong path | Use full project path |
| `job not running` | Rules don't match | Check `rules:` conditions |
| `cache miss` | Key changed | Verify `cache.key` pattern |
| `permission denied` | Private project | Add CI token or make shared repo public |
