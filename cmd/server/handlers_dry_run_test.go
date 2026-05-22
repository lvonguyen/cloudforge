package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"aegis/pkg/remediation"
)

// TestDryRunRemediation_ViewerCanRead confirms the Viewer+ role chain decided
// in design discussion. Dry-run is non-mutating prediction; the matching
// auth tier is the same as GET /remediations/{id}.
func TestDryRunRemediation_ViewerCanRead(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/dry-run", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result remediation.DryRunResult
	assertJSON(t, rr, &result)

	if result.FindingID == "" {
		t.Errorf("policy must always set FindingID (got empty)")
	}
	if result.EstimatedImpact == "" {
		t.Errorf("policy must set EstimatedImpact (got empty)")
	}
}

func TestDryRunRemediation_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-does-not-exist/dry-run", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}

func TestDryRunRemediation_RequiresAuth(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/dry-run", "", "")
	if rr.Code == http.StatusOK {
		t.Errorf("status = 200, want non-OK without auth")
	}
}

// TestDryRunRemediation_ResponseShape asserts the JSON contract the drawer
// consumes. The drawer projects directly into DryRunResult — these are the
// fields it reads. If you add fields to the policy, extend this assertion.
func TestDryRunRemediation_ResponseShape(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/dry-run", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var asMap map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &asMap); err != nil {
		t.Fatalf("response body is not JSON object: %v", err)
	}
	for _, k := range []string{"finding_id", "would_succeed", "prerequisites_met", "estimated_impact"} {
		if _, ok := asMap[k]; !ok {
			t.Errorf("response missing required field %q", k)
		}
	}
}

// TestDryRunPolicy_Decisions exercises the pure dryRunPolicy() function
// across the {Status, Tier, Handler} matrix that drives the predicate. Each
// axis is independent, so cases vary one knob at a time.
func TestDryRunPolicy_Decisions(t *testing.T) {
	type expect struct {
		wouldSucceed     bool
		prerequisitesMet bool
		warningSubstrs   []string
		impactSubstr     string
	}
	cases := []struct {
		name string
		rem  RemediationRecord
		want expect
	}{
		{
			name: "pending tier-1 auto-safe — clean run",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-1", Tier: 1, Handler: "sg-rule-remediator", Status: "pending"},
			want: expect{wouldSucceed: true, prerequisitesMet: true, impactSubstr: "Tier 1 sg-rule-remediator"},
		},
		{
			name: "pending tier-3 needs change-window approval",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-2", Tier: 3, Handler: "rds-access-remediator", Status: "pending"},
			want: expect{wouldSucceed: true, prerequisitesMet: false, warningSubstrs: []string{"change-window"}, impactSubstr: "Tier 3"},
		},
		{
			name: "completed not actionable",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-3", Tier: 2, Handler: "iam-policy-scoper", Status: "completed"},
			want: expect{wouldSucceed: false, prerequisitesMet: true, warningSubstrs: []string{"already executed"}, impactSubstr: "(status: completed)"},
		},
		{
			name: "failed allowed to retry with warning",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-4", Tier: 2, Handler: "encryption-enabler", Status: "failed"},
			want: expect{wouldSucceed: true, prerequisitesMet: true, warningSubstrs: []string{"previous attempt failed"}, impactSubstr: "Tier 2 encryption-enabler"},
		},
		{
			name: "in_progress blocks rerun",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-5", Tier: 1, Handler: "tag-enforcer", Status: "in_progress"},
			want: expect{wouldSucceed: false, prerequisitesMet: true, warningSubstrs: []string{"already running"}, impactSubstr: "Tier 1"},
		},
		{
			name: "manual-escalation warns and needs change-window",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-6", Tier: 3, Handler: "manual-escalation", Status: "pending"},
			want: expect{wouldSucceed: true, prerequisitesMet: false, warningSubstrs: []string{"manual remediation", "change-window"}, impactSubstr: "manual-escalation"},
		},
		{
			name: "skipped allowed to retry",
			rem:  RemediationRecord{ID: "rem-x", FindingID: "f-7", Tier: 2, Handler: "nsg-rule-remediator", Status: "skipped"},
			want: expect{wouldSucceed: true, prerequisitesMet: true, warningSubstrs: []string{"previously skipped"}, impactSubstr: "nsg-rule-remediator"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dryRunPolicy(&tc.rem)

			if got.WouldSucceed != tc.want.wouldSucceed {
				t.Errorf("WouldSucceed = %v, want %v", got.WouldSucceed, tc.want.wouldSucceed)
			}
			if got.PrerequisitesMet != tc.want.prerequisitesMet {
				t.Errorf("PrerequisitesMet = %v, want %v", got.PrerequisitesMet, tc.want.prerequisitesMet)
			}
			for _, sub := range tc.want.warningSubstrs {
				found := false
				for _, w := range got.Warnings {
					if strings.Contains(w, sub) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Warnings %v missing expected substring %q", got.Warnings, sub)
				}
			}
			if !strings.Contains(got.EstimatedImpact, tc.want.impactSubstr) {
				t.Errorf("EstimatedImpact = %q, want substring %q", got.EstimatedImpact, tc.want.impactSubstr)
			}
			if got.FindingID != tc.rem.FindingID {
				t.Errorf("FindingID = %q, want %q", got.FindingID, tc.rem.FindingID)
			}
		})
	}
}
