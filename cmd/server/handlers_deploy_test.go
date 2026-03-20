package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestStartDeployPreview_Success(t *testing.T) {
	_, router := testServer(t)

	body := `{"resourceType":"s3","provider":"aws","region":"us-east-1","appId":"demo-app"}`
	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, adminJWT(t))
	assertStatus(t, rr, http.StatusAccepted)

	var resp map[string]string
	assertJSON(t, rr, &resp)

	execID, ok := resp["execution_id"]
	if !ok {
		t.Fatal("response missing execution_id field")
	}
	if !strings.HasPrefix(execID, "exec-") {
		t.Errorf("execution_id = %q, want prefix %q", execID, "exec-")
	}
}

func TestStartDeployPreview_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)

	body := `{"resourceType":"lambda","provider":"aws","region":"us-west-2"}`
	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, operatorJWT(t))
	assertStatus(t, rr, http.StatusAccepted)
}

func TestStartDeployPreview_MissingFields(t *testing.T) {
	_, router := testServer(t)

	// resourceType is missing
	body := `{"provider":"aws","region":"us-east-1"}`
	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, adminJWT(t))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestStartDeployPreview_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	body := `{"resourceType":"s3","provider":"aws","region":"us-east-1"}`
	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestStartDeployPreview_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)

	body := `{"resourceType":"s3","provider":"aws","region":"us-east-1"}`
	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, viewerJWT(t))
	if rr.Code == http.StatusForbidden { t.Errorf("status = 403, want non-forbidden (viewer parity)") }
}

func TestAbortDeployPreview_NotFound(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview/exec-nonexistent/abort", "", adminJWT(t))
	assertStatus(t, rr, http.StatusNotFound)
}

func TestAbortDeployPreview_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/deploy/preview/exec-abc123/abort", "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestAbortDeployPreview_Success(t *testing.T) {
	_, router := testServer(t)

	// Start a preview to get a real execution ID.
	body := `{"resourceType":"rds","provider":"aws","region":"eu-west-1"}`
	startRR := doRequest(t, router, "POST", "/api/v1/deploy/preview", body, adminJWT(t))
	assertStatus(t, startRR, http.StatusAccepted)

	var startResp map[string]string
	if err := json.NewDecoder(startRR.Body).Decode(&startResp); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	execID := startResp["execution_id"]

	// Abort the execution.
	abortRR := doRequest(t, router, "POST", "/api/v1/deploy/preview/"+execID+"/abort", "", adminJWT(t))
	assertStatus(t, abortRR, http.StatusOK)

	var abortResp map[string]string
	assertJSON(t, abortRR, &abortResp)
	if abortResp["status"] != "aborted" {
		t.Errorf("abort status = %q, want %q", abortResp["status"], "aborted")
	}
}

func TestDeployTracker_AddAbort(t *testing.T) {
	dt := newDeployTracker()

	called := false
	cancel := context.CancelFunc(func() { called = true })

	dt.add("exec-test01", cancel)

	// First abort should succeed and invoke the cancel func.
	if !dt.abort("exec-test01") {
		t.Error("first abort: want true, got false")
	}
	if !called {
		t.Error("cancel func was not called on abort")
	}

	// Second abort on the same ID should return false (already removed).
	if dt.abort("exec-test01") {
		t.Error("second abort: want false, got true")
	}
}

func TestGenerateExecID_Format(t *testing.T) {
	id := generateExecID()

	// Must start with "exec-".
	if !strings.HasPrefix(id, "exec-") {
		t.Errorf("generateExecID() = %q, want prefix %q", id, "exec-")
	}

	// "exec-" (5) + 16 hex chars = 21 total.
	const wantLen = 21
	if len(id) != wantLen {
		t.Errorf("len(generateExecID()) = %d, want %d; id = %q", len(id), wantLen, id)
	}

	// The hex portion must be lowercase hex.
	hexPart := id[len("exec-"):]
	for i, ch := range hexPart {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("hex part contains non-hex char %q at index %d; id = %q", ch, i, id)
		}
	}
}
