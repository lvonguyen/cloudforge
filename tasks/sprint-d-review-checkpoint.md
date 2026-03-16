# Sprint D — Full-Stack Review Checkpoint

**When:** After all Sprint D commits land and tests pass.
**Purpose:** Validate the security-hardened, accessibility-improved, decomposed codebase before the whitelabel architecture sprint changes the surface area.
**Protocol:** AGENT_REVIEW_ITERATION_PROTOCOL.md v1.3.0

---

## Rationale

This checkpoint lands here — after D, before E — for three reasons:

1. **Clean security baseline.** All security debt (D1 localStorage escalation, D2 OPA fail-open) is closed. The review validates a known-clean state rather than reviewing against open findings.
2. **Before surface area change.** Sprint E (whitelabel) restructures the provider architecture across multiple packages. Reviewing before that change keeps the diff scope bounded and findings actionable.
3. **Component boundaries are fresh.** D7 decomposes PolicyDetail (927L) and Request (725L). The review catches structural issues in those new boundaries while they are still cheap to adjust.

---

## Phase 1: 3-Agent Blind Review

Spawn in parallel (all on Sonnet):

1. **quality-review agent** — KISS/YAGNI, code smells, readability, component decomposition quality (especially D7 refactors)
2. **bug-discovery agent** — Race conditions, nil handling, edge cases, auth flow correctness (especially D1 fix)
3. **security-audit agent** — OWASP, input validation, XSS, auth bypass, OPA policy correctness (especially D1 + D2 fixes)

All agents review the full diff from Sprint C HEAD to Sprint D HEAD:

```bash
git diff <sprint-c-sha>...HEAD
```

---

## Phase 2: Opus Distiller

After all 3 workers complete, spawn Opus distiller to:

- Deduplicate findings across agents
- Priority-rank by severity (CRITICAL > HIGH > MEDIUM > LOW)
- Produce compressed FIX/ACCEPT summary (~500-1K tokens)
- Flag any finding >= HIGH as blocking

---

## Phase 3: Chrome QA Sweep

Run `/ap-chrome-qa` (or `/chrome-qa`) against all routes to validate:

- Accessibility fixes from D5 are visible (aria-labels, heading order, focus trap)
- Severity colors from D6 are consistent across all views
- Decomposed components from D7 render correctly
- No visual regressions from D1-D4 backend changes

---

## Threshold

All scoring dimensions must reach **>= 4.5/5** before proceeding to Sprint E.
Max 3 iterations. If threshold not met after 3 iterations, escalate to manual review.

---

## Exit Criteria

- [ ] quality-review >= 4.5/5 across all dimensions
- [ ] bug-discovery >= 4.5/5 across all dimensions
- [ ] security-audit >= 4.5/5 across all dimensions
- [ ] Chrome QA sweep: zero blocking findings on all routes
- [ ] All findings >= HIGH resolved and re-reviewed
- [ ] Opus distiller summary archived to `tasks/sprint-d-review-findings.md`
