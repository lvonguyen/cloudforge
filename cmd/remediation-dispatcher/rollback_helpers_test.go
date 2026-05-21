package main

import (
	"testing"
	"time"

	"aegis/pkg/remediation"
)

func TestRollbackStateFromSnapshotUsesCapturedPreState(t *testing.T) {
	capturedAt := time.Date(2026, 2, 27, 10, 5, 32, 0, time.UTC)
	state := RemediationState{
		FindingID: "f-aws-0038",
		Timestamp: capturedAt,
		PreState: map[string]interface{}{
			"resource_id": "s3://mission-artifacts",
			"region":      "us-gov-west-1",
			"account_id":  "999988887777",
		},
		Result: &remediation.RemediationResult{
			ResourceID: "fallback-resource",
		},
	}

	rollbackState := rollbackStateFromSnapshot(state)

	if rollbackState.FindingID != "f-aws-0038" {
		t.Fatalf("unexpected finding id: %s", rollbackState.FindingID)
	}
	if rollbackState.ResourceID != "s3://mission-artifacts" {
		t.Fatalf("expected captured resource id, got %s", rollbackState.ResourceID)
	}
	if rollbackState.Region != "us-gov-west-1" {
		t.Fatalf("unexpected region: %s", rollbackState.Region)
	}
	if rollbackState.AccountID != "999988887777" {
		t.Fatalf("unexpected account id: %s", rollbackState.AccountID)
	}
	if !rollbackState.CapturedAt.Equal(capturedAt) {
		t.Fatalf("unexpected captured time: %s", rollbackState.CapturedAt)
	}
}

func TestDeactivatedKeyIDsFromStateSupportsJSONStringSlices(t *testing.T) {
	keys, ok := deactivatedKeyIDsFromState(map[string]interface{}{
		"deactivated_key_ids": []interface{}{"AKIAONE", "AKIATWO"},
	})
	if !ok || len(keys) != 2 || keys[0] != "AKIAONE" || keys[1] != "AKIATWO" {
		t.Fatalf("unexpected JSON-style keys: %#v ok=%v", keys, ok)
	}

	keys, ok = deactivatedKeyIDsFromState(map[string]interface{}{
		"deactivated_key_ids": []string{"AKIATHREE"},
	})
	if !ok || len(keys) != 1 || keys[0] != "AKIATHREE" {
		t.Fatalf("unexpected native keys: %#v ok=%v", keys, ok)
	}
}
