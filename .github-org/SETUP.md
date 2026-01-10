# Organization `.github` Repository Setup

This directory contains the structure for the `lvonguyen/.github` repository.

---

## [>] Quick Setup

```bash
# 1. Create the .github repo in your org/account
gh repo create lvonguyen/.github --public --description "Default community health files and workflow templates"

# 2. Clone and copy contents
git clone https://github.com/lvonguyen/.github.git
cd .github

# 3. Copy contents from this directory (excluding SETUP.md)
cp -r /path/to/.github-org/* .
rm SETUP.md

# 4. Push
git add .
git commit -m "feat: Add org-level defaults and workflow templates"
git push
```

---

## [/] Directory Structure

```
.github/
├── profile/
│   └── README.md              # Org profile (shows on github.com/lvonguyen)
├── workflow-templates/
│   ├── go-ci.yml              # Go CI template
│   ├── go-ci.properties.json
│   ├── python-ci.yml          # Python CI template
│   ├── python-ci.properties.json
│   ├── terraform-ci.yml       # Terraform CI template
│   └── terraform-ci.properties.json
├── CONTRIBUTING.md            # Default for all repos
├── CODE_OF_CONDUCT.md         # Default for all repos
├── SECURITY.md                # Default for all repos
└── FUNDING.yml                # GitHub Sponsors
```

---

## [+] How It Works

### Default Community Health Files
Files like `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md` automatically apply to ALL repos in the org that don't have their own versions.

### Workflow Templates
When you click "Actions" -> "New workflow" in any repo, your templates appear under "By lvonguyen":

```
[Go CI]        - For repos with go.mod
[Python CI]    - For repos with pyproject.toml
[Terraform CI] - For repos with *.tf files
```

---

## [!] Org Settings for New Repos

Go to: **github.com/organizations/lvonguyen/settings**

### Repository Defaults
**Settings -> Repository -> Repository defaults**

1. **Default branch name:** `main`
2. **Repository labels:** Add standard labels
   - `bug`, `enhancement`, `documentation`, `security`, `good first issue`

### Actions Permissions
**Settings -> Actions -> General**

1. [x] Allow all actions and reusable workflows
2. [x] Allow GitHub Actions to create PRs
3. Workflow permissions: Read and write

### Branch Protection (Rulesets)
**Settings -> Rules -> Rulesets -> New ruleset**

Create org-wide ruleset for `main` branch:

| Setting | Value |
|---------|-------|
| Name | `protect-main` |
| Enforcement | Active |
| Target | Default branch |
| Bypass | Repository admins only |

Rules:
- [x] Require pull request before merging
- [x] Require approvals (1)
- [x] Dismiss stale reviews
- [x] Require status checks to pass
- [x] Require branches to be up to date
- [x] Block force pushes

**Apply to:** All repositories (or select specific ones)

---

## [>] Adding Workflow Templates

To add a new template:

1. Create `workflow-templates/my-workflow.yml`
2. Create `workflow-templates/my-workflow.properties.json`:

```json
{
  "name": "My Workflow",
  "description": "Description shown in UI",
  "iconName": "octicon icon name",
  "categories": ["Category"],
  "filePatterns": ["pattern-to-match"]
}
```

Icon names: https://primer.style/octicons/

---

## [/] Per-Repo Override

Individual repos can override org defaults by creating their own:
- `.github/workflows/ci.yml` - Custom CI
- `CONTRIBUTING.md` - Custom contributing guide
- `SECURITY.md` - Custom security policy

---

## [+] Minimal Repo CI (Calls Template)

For repos that want to use the template directly, create:

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  ci:
    uses: lvonguyen/.github/.github/workflows/go-ci.yml@main
```

Note: This requires workflows to be in `.github/workflows/` not `workflow-templates/`.

---

## [!] Important Notes

1. **Workflow templates** are suggestions - repos must manually add them
2. **Reusable workflows** can be called but need a local file to invoke
3. **Community health files** apply automatically (no action needed)
4. **Rulesets** can enforce branch protection org-wide (recommended)
