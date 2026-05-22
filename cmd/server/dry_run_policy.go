package main

import (
	"fmt"

	"aegis/pkg/remediation"
)

// dryRunPolicy projects a RemediationRecord into a simulated DryRunResult.
//
// The server is a façade — it never invokes real Remediator.DryRun()
// implementations (those live in internal/remediation/* and execute inside
// the remediation-dispatcher binary). This function predicts outcome from
// the record alone: Status, Tier, Handler, FindingID.
//
// The frontend's HANDLER_CATALOG owns the rich UI fields (planned actions
// text, permissions, rollback steps). This function owns the predicate:
// can this remediation execute right now, and what should the operator be
// warned about before approving?
//
// Three orthogonal decisions are encoded here:
//
//  1. Status -> WouldSucceed.   pending/failed/skipped can run; completed
//                               (already done) and in_progress (already
//                               running) cannot.
//  2. Tier   -> PrerequisitesMet. Tiers 1-2 are self-prerequisite-clearing;
//                               Tier 3 needs a human change-window approver
//                               that isn't recorded on the record itself.
//  3. Handler -> SDK availability. manual-escalation has no automated path
//                               and warns explicitly so operators don't
//                               expect a one-click execution.
//
// PlannedActions / RollbackPlan / EstimatedRollbackWindow / ValidationChecks
// are intentionally left nil — the frontend merges its catalog data on top.
//
// Constraint: deterministic. No clock reads, no I/O, no random. Tests assert
// specific outputs for canned input records.
func dryRunPolicy(rem *RemediationRecord) *remediation.DryRunResult {
	result := &remediation.DryRunResult{
		FindingID: rem.FindingID,
		EstimatedImpact: fmt.Sprintf(
			"Tier %d %s on finding %s (status: %s)",
			rem.Tier, rem.Handler, rem.FindingID, rem.Status,
		),
	}

	switch rem.Status {
	case "pending", "failed", "skipped":
		result.WouldSucceed = true
	}

	switch rem.Status {
	case "completed":
		result.Warnings = append(result.Warnings, "remediation already executed successfully")
	case "in_progress":
		result.Warnings = append(result.Warnings, "remediation is already running")
	case "failed":
		result.Warnings = append(result.Warnings, "previous attempt failed — verify root cause before retry")
	case "skipped":
		result.Warnings = append(result.Warnings, "previously skipped by operator")
	}

	result.PrerequisitesMet = rem.Tier < 3
	if rem.Tier == 3 {
		result.Warnings = append(result.Warnings, "tier-3 remediation requires change-window approval before execute")
	}

	if rem.Handler == "manual-escalation" {
		result.Warnings = append(result.Warnings, "manual remediation — no automated SDK action available")
	}

	return result
}
