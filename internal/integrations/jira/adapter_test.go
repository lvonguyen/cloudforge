package jira

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestAdapterListComments(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if got := r.URL.Path; got != "/rest/api/3/issue/CVRT-42/comment" {
			t.Fatalf("path = %s, want /rest/api/3/issue/CVRT-42/comment", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"comments": [
				{
					"id": "10001",
					"created": "2026-03-30T12:00:00.000-0700",
					"author": { "displayName": "Jira Bot" },
					"body": {
						"type": "doc",
						"version": 1,
						"content": [
							{
								"type": "paragraph",
								"content": [
									{ "type": "text", "text": "Escalated to platform team." }
								]
							}
						]
					}
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL:          server.URL,
		Username:         "jira@example.com",
		APIToken:         "token",
		ProjectKey:       "CVRT",
		DefaultIssueType: "Task",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	adapter := &Adapter{client: client, logger: zap.NewNop()}
	comments, err := adapter.ListComments(context.Background(), "CVRT-42")
	if err != nil {
		t.Fatalf("ListComments: %v", err)
	}
	if len(comments) != 1 {
		t.Fatalf("comment count = %d, want 1", len(comments))
	}
	if comments[0].Body != "Escalated to platform team." {
		t.Fatalf("body = %q, want Escalated to platform team.", comments[0].Body)
	}
	if comments[0].Author != "Jira Bot" {
		t.Fatalf("author = %q, want Jira Bot", comments[0].Author)
	}
}
