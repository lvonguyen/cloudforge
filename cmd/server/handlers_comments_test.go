package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// testFindingID is a real ID from the trimmed test fixture (findings_test.json).
const testFindingID = "f-14868"

func TestListComments_Empty(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/"+testFindingID+"/comments", "", adminJWT(t))
	assertStatus(t, rr, http.StatusOK)

	var comments []FindingComment
	assertJSON(t, rr, &comments)
	if len(comments) != 0 {
		t.Errorf("expected 0 comments, got %d", len(comments))
	}
}

func TestAddComment_Success(t *testing.T) {
	_, router := testServer(t)

	body := `{"body":"test comment"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/"+testFindingID+"/comments", body, operatorJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	var comment FindingComment
	assertJSON(t, rr, &comment)
	if comment.Body != "test comment" {
		t.Errorf("body = %q, want %q", comment.Body, "test comment")
	}
	if comment.Author != "test-operator" {
		t.Errorf("author = %q, want %q", comment.Author, "test-operator")
	}
	if comment.FindingID != testFindingID {
		t.Errorf("finding_id = %q, want %q", comment.FindingID, testFindingID)
	}
	if comment.ID == "" {
		t.Error("expected non-empty comment ID")
	}
}

func TestAddComment_ThenList(t *testing.T) {
	srv, router := testServer(t)
	_ = srv // server used implicitly via shared router

	body := `{"body":"hello world"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/f-02024/comments", body, adminJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	rr = doRequest(t, router, "GET", "/api/v1/findings/f-02024/comments", "", adminJWT(t))
	assertStatus(t, rr, http.StatusOK)

	var comments []FindingComment
	assertJSON(t, rr, &comments)
	if len(comments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(comments))
	}
	if comments[0].Body != "hello world" {
		t.Errorf("body = %q, want %q", comments[0].Body, "hello world")
	}
}

func TestAddComment_EmptyBody(t *testing.T) {
	_, router := testServer(t)

	body := `{"body":""}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/"+testFindingID+"/comments", body, operatorJWT(t))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestAddComment_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)

	body := `{"body":"viewer comment"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/"+testFindingID+"/comments", body, viewerJWT(t))
	assertStatus(t, rr, http.StatusForbidden)
}

func TestDeleteComment_AdminOnly(t *testing.T) {
	_, router := testServer(t)

	// Create a comment with admin
	body := `{"body":"to be deleted"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/f-00486/comments", body, adminJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	var created FindingComment
	assertJSON(t, rr, &created)

	// Operator cannot delete
	rr = doRequest(t, router, "DELETE", "/api/v1/findings/f-00486/comments/"+created.ID, "", operatorJWT(t))
	assertStatus(t, rr, http.StatusForbidden)

	// Admin can delete
	rr = doRequest(t, router, "DELETE", "/api/v1/findings/f-00486/comments/"+created.ID, "", adminJWT(t))
	assertStatus(t, rr, http.StatusNoContent)

	// Verify comment is gone
	rr = doRequest(t, router, "GET", "/api/v1/findings/f-00486/comments", "", adminJWT(t))
	assertStatus(t, rr, http.StatusOK)

	var remaining []FindingComment
	assertJSON(t, rr, &remaining)
	if len(remaining) != 0 {
		t.Errorf("expected 0 comments after delete, got %d", len(remaining))
	}
}

func TestAddComment_NonExistentFinding(t *testing.T) {
	_, router := testServer(t)

	body := `{"body":"orphan comment"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/DOES-NOT-EXIST/comments", body, operatorJWT(t))
	assertStatus(t, rr, http.StatusNotFound)
}

func TestDeleteComment_NotFound(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "DELETE", "/api/v1/findings/f-123/comments/nonexistent", "", adminJWT(t))
	assertStatus(t, rr, http.StatusNotFound)

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp["error"] != "comment not found" {
		t.Errorf("error = %q, want %q", resp["error"], "comment not found")
	}
}
