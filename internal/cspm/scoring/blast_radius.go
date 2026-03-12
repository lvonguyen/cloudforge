package scoring

import "strings"

// ComputeBlastRadius estimates the number of findings affected if the given
// finding is exploited. It counts other findings that share the same account,
// VPC/subnet (via VPCType), or are otherwise reachable from the same network
// segment. A critical finding in a production account with many co-located
// findings has a high blast radius.
//
// The result is suitable for populating FindingContext.BlastRadiusCount.
func ComputeBlastRadius(finding Finding, allFindings []Finding) int {
	affected := make(map[string]bool)

	for _, other := range allFindings {
		if other.ID == finding.ID {
			continue
		}
		if isBlastReachable(finding, other) {
			affected[other.ID] = true
		}
	}

	return len(affected)
}

// isBlastReachable determines if 'other' would be affected by exploitation of 'source'.
// Two findings are considered reachable when they share any of:
//   - Same account ID
//   - Same VPC type (shared or transit) within the same account
//   - Same region + same account (network-adjacent)
//
// Production environment findings carry greater weight: a production finding in
// the same account always counts as reachable.
func isBlastReachable(source, other Finding) bool {
	// Rule 1: Same account — findings in the same account share IAM boundary.
	if source.AccountID != "" && source.AccountID == other.AccountID {
		return true
	}

	// Rule 2: Shared or transit VPC — lateral movement across VPCs.
	if isSharedNetwork(source, other) {
		return true
	}

	// Rule 3: Same region across accounts with shared VPC types.
	if source.Region != "" && source.Region == other.Region {
		if source.Context.VPCType == "transit" && other.Context.VPCType == "transit" {
			return true
		}
	}

	return false
}

// isSharedNetwork returns true when both findings are in a shared or transit
// VPC configuration, even across accounts — these can have cross-account peering.
func isSharedNetwork(a, b Finding) bool {
	aVPC := strings.ToLower(a.Context.VPCType)
	bVPC := strings.ToLower(b.Context.VPCType)

	if aVPC == "" || bVPC == "" {
		return false
	}

	// Shared VPCs within the same account are directly reachable.
	if a.AccountID == b.AccountID && (aVPC == "shared" || bVPC == "shared") {
		return true
	}

	// Transit VPCs are designed for cross-account connectivity.
	if aVPC == "transit" && bVPC == "transit" {
		return true
	}

	return false
}
