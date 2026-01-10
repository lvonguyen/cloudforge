# Commit Message Convention

**Version:** 1.0
**Last Updated:** January 2026

---

## Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

---

## Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code change, no new feature/fix |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `ci` | CI/CD changes |
| `chore` | Maintenance, deps, tooling |
| `security` | Security fix/improvement |

---

## Scope (Optional)

Module or area affected:

```
feat(api): Add rate limiting middleware
fix(grc): Resolve N+1 query in postgres provider
docs(adr): Add ADR-007 for caching strategy
ci(gitlab): Add Python CI template
```

---

## Rules

```
[+] DO:
- Use imperative mood ("Add" not "Added")
- Keep subject under 72 chars
- Capitalize first letter of subject
- No period at end of subject
- Separate subject from body with blank line

[-] DON'T:
- No emojis
- No Co-Authored-By trailers
- No WIP commits to main
```

---

## Examples

**Simple:**
```
fix: Resolve authentication timeout issue
```

**With scope:**
```
feat(compliance): Add NIST 800-171 framework support
```

**With body:**
```
refactor(grc): Extract provider interface to separate package

- Move GRCProvider interface to internal/domain/grc
- Update all implementations to use new location
- Add interface documentation
```

**Breaking change:**
```
feat(api)!: Change exception response format

BREAKING CHANGE: Response now returns array instead of object.
Update all API clients accordingly.
```

**With issue reference:**
```
fix(workflow): Resolve approval timeout race condition

Fixes #42
```

---

## Quick Reference

```bash
# Feature
git commit -m "feat(module): Add new capability"

# Bug fix
git commit -m "fix(module): Resolve issue description"

# Docs
git commit -m "docs: Update README with examples"

# CI/CD
git commit -m "ci: Add GitHub Actions workflow"

# Breaking change
git commit -m "feat(api)!: Change response format"
```
