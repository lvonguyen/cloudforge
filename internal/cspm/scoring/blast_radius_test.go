package scoring

import "testing"

// --- Helper constructors for blast radius tests ---

func blastFinding(id, accountID, region, vpcType, envType string) Finding {
	return Finding{
		ID:        id,
		AccountID: accountID,
		Region:    region,
		Context: FindingContext{
			VPCType: vpcType,
			EnvType: envType,
		},
	}
}

// --- Tests for ComputeBlastRadius ---

func TestBlastRadius_SameAccount_CountsAll(t *testing.T) {
	target := blastFinding("target-001", "acct-1", "us-east-1", "isolated", "prod")

	all := []Finding{
		target,
		blastFinding("peer-001", "acct-1", "us-east-1", "isolated", "prod"),
		blastFinding("peer-002", "acct-1", "us-west-2", "isolated", "prod"),
		blastFinding("peer-003", "acct-1", "eu-west-1", "shared", "staging"),
	}

	radius := ComputeBlastRadius(target, all)

	// 3 peers in same account (excluding self).
	if radius != 3 {
		t.Errorf("expected blast radius 3 (same account), got %d", radius)
	}
}

func TestBlastRadius_DifferentAccount_Isolated_NotCounted(t *testing.T) {
	target := blastFinding("target-002", "acct-1", "us-east-1", "isolated", "prod")

	all := []Finding{
		target,
		blastFinding("other-001", "acct-2", "us-east-1", "isolated", "prod"),
		blastFinding("other-002", "acct-3", "us-east-1", "isolated", "prod"),
	}

	radius := ComputeBlastRadius(target, all)

	// Different accounts with isolated VPCs are not reachable.
	if radius != 0 {
		t.Errorf("expected blast radius 0 (different accounts, isolated), got %d", radius)
	}
}

func TestBlastRadius_TransitVPC_CrossAccount(t *testing.T) {
	target := blastFinding("target-003", "acct-1", "us-east-1", "transit", "prod")

	all := []Finding{
		target,
		blastFinding("transit-001", "acct-2", "us-east-1", "transit", "prod"),
		blastFinding("transit-002", "acct-3", "us-east-1", "transit", "staging"),
		blastFinding("isolated-001", "acct-4", "us-east-1", "isolated", "prod"),
	}

	radius := ComputeBlastRadius(target, all)

	// Transit VPCs in same region are reachable across accounts (2 matches).
	// Isolated VPC in different account is not.
	if radius != 2 {
		t.Errorf("expected blast radius 2 (transit VPC peers), got %d", radius)
	}
}

func TestBlastRadius_SharedVPC_SameAccount(t *testing.T) {
	target := blastFinding("target-004", "acct-1", "us-east-1", "shared", "prod")

	all := []Finding{
		target,
		blastFinding("shared-001", "acct-1", "us-east-1", "shared", "prod"),
		blastFinding("shared-002", "acct-1", "us-west-2", "shared", "staging"),
		blastFinding("isolated-001", "acct-2", "us-east-1", "shared", "prod"), // diff account
	}

	radius := ComputeBlastRadius(target, all)

	// Same-account findings are always reachable (2 peers).
	// Different-account shared VPC without transit is not reachable.
	if radius != 2 {
		t.Errorf("expected blast radius 2 (shared VPC same account), got %d", radius)
	}
}

func TestBlastRadius_EmptyFindings_Zero(t *testing.T) {
	target := blastFinding("target-005", "acct-1", "us-east-1", "", "prod")

	radius := ComputeBlastRadius(target, nil)
	if radius != 0 {
		t.Errorf("expected blast radius 0 for nil findings, got %d", radius)
	}
}

func TestBlastRadius_OnlySelf_Zero(t *testing.T) {
	target := blastFinding("target-006", "acct-1", "us-east-1", "shared", "prod")

	all := []Finding{target}

	radius := ComputeBlastRadius(target, all)
	if radius != 0 {
		t.Errorf("expected blast radius 0 when only self present, got %d", radius)
	}
}

func TestBlastRadius_ProdAccountWith50Findings_HighRadius(t *testing.T) {
	target := blastFinding("target-007", "prod-acct", "us-east-1", "shared", "prod")
	target.Severity = SevCritical

	all := []Finding{target}
	for i := 0; i < 50; i++ {
		f := blastFinding("peer-"+string(rune('A'+i%26))+"-"+string(rune('0'+i/26)),
			"prod-acct", "us-east-1", "shared", "prod")
		f.ID = "peer-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		all = append(all, f)
	}

	radius := ComputeBlastRadius(target, all)

	if radius != 50 {
		t.Errorf("expected blast radius 50 for production account with 50 peers, got %d", radius)
	}
}

func TestBlastRadius_NoDuplicateCounting(t *testing.T) {
	// A finding that matches multiple rules should only be counted once.
	target := blastFinding("target-008", "acct-1", "us-east-1", "transit", "prod")

	peer := blastFinding("peer-008", "acct-1", "us-east-1", "transit", "prod")
	// peer matches: same account, transit VPC same region, shared network.

	all := []Finding{target, peer}

	radius := ComputeBlastRadius(target, all)

	if radius != 1 {
		t.Errorf("expected blast radius 1 (no duplicates), got %d", radius)
	}
}

func TestBlastRadius_EmptyAccountID_NoMatch(t *testing.T) {
	target := blastFinding("target-009", "", "us-east-1", "", "prod")
	peer := blastFinding("peer-009", "", "us-east-1", "", "prod")

	all := []Finding{target, peer}

	radius := ComputeBlastRadius(target, all)

	// Empty account IDs should not match each other.
	if radius != 0 {
		t.Errorf("expected blast radius 0 for empty account IDs, got %d", radius)
	}
}
