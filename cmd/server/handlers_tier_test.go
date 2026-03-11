package main

import (
	"net/http"
	"testing"
)

// TestListRemediations_InvalidTier_Returns400 verifies that the listRemediations
// handler rejects a malformed ?tier= query parameter with HTTP 400.
//
// Before the fix, the handler used:
//
//	tierVal, err = strconv.Atoi(tierFilter)
//	if err == nil { hasTier = true }
//
// When Atoi fails (e.g. tier="abc"), the condition is false, hasTier stays
// false, and the invalid parameter is silently ignored — the handler returns
// all remediations as if no tier filter was provided. Non-numeric errors from
// Atoi were swallowed.
//
// After the fix, the handler checks if err != nil and returns 400 Bad Request.
func TestListRemediations_InvalidTier_Returns400(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations?tier=abc", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

// TestListRemediations_ValidTier_Returns200 verifies that a valid integer tier
// filter still works correctly after the fix.
func TestListRemediations_ValidTier_Returns200(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/remediations?tier=1", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var results []RemediationRecord
	assertJSON(t, rr, &results)

	for _, rem := range results {
		if rem.Tier != 1 {
			t.Errorf("remediation %s tier = %d, want 1", rem.ID, rem.Tier)
		}
	}
}
