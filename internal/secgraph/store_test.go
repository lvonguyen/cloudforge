package secgraph

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

type captureCall struct {
	query string
	args  []any
}

type captureExec struct {
	calls []captureCall
}

func (c *captureExec) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	c.calls = append(c.calls, captureCall{
		query: query,
		args:  append([]any(nil), args...),
	})
	return stubResult(1), nil
}

type stubResult int64

func (r stubResult) LastInsertId() (int64, error) {
	return int64(r), nil
}

func (r stubResult) RowsAffected() (int64, error) {
	return int64(r), nil
}

func TestUpsertEvaluationUsesDatabaseGeneratedUUID(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_774_994_991, 0).UTC()
	evaluation := ControlEvaluation{
		ID:          "EVAL-00001A334E1D",
		ControlID:   "cis_aws_1_1",
		ResourceID:  "arn:aws:s3:::example",
		Status:      EvalFail,
		Evidence:    []string{"finding-1"},
		EvaluatedAt: now,
		TenantID:    "default",
	}
	execer := &captureExec{}

	store := &Store{}
	if err := store.upsertEvaluation(context.Background(), execer, evaluation); err != nil {
		t.Fatalf("upsertEvaluation() error = %v", err)
	}

	if got := len(execer.calls); got != 1 {
		t.Fatalf("ExecContext calls = %d, want 1", got)
	}

	call := execer.calls[0]
	if got := len(call.args); got != 6 {
		t.Fatalf("ExecContext args = %d, want 6", got)
	}

	if got := call.args[0]; got != evaluation.ControlID {
		t.Fatalf("first arg = %v, want control_id %q", got, evaluation.ControlID)
	}

	if got := call.args[5]; got != evaluation.TenantID {
		t.Fatalf("last arg = %v, want tenant_id %q", got, evaluation.TenantID)
	}
}

func TestUpsertMaterializationBatchesIssueSurfaceWrites(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_774_995_186, 0).UTC()
	result := MaterializationResult{
		Evaluations: []ControlEvaluation{
			{
				ID:          "EVAL-1",
				ControlID:   "ctrl-1",
				ResourceID:  "res-1",
				Status:      EvalFail,
				Evidence:    []string{"f-1"},
				EvaluatedAt: now,
				TenantID:    "default",
			},
			{
				ID:          "EVAL-2",
				ControlID:   "ctrl-2",
				ResourceID:  "res-2",
				Status:      EvalPass,
				Evidence:    []string{"f-2"},
				EvaluatedAt: now,
				TenantID:    "default",
			},
		},
		Issues: []Issue{
			{
				ID:          "ISS-1",
				Title:       "issue 1",
				Description: "desc 1",
				Severity:    "HIGH",
				Status:      IssueOpen,
				TenantID:    "default",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "ISS-2",
				Title:       "issue 2",
				Description: "desc 2",
				Severity:    "MEDIUM",
				Status:      IssueOpen,
				TenantID:    "default",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		IssueFindings: []IssueFindingLink{
			{IssueID: "ISS-1", FindingID: "f-1", CreatedAt: now},
			{IssueID: "ISS-2", FindingID: "f-2", CreatedAt: now},
		},
	}
	execer := &captureExec{}
	store := &Store{}

	if err := store.upsertEvaluationBatch(context.Background(), execer, result.Evaluations); err != nil {
		t.Fatalf("upsertEvaluationBatch() error = %v", err)
	}
	if err := store.upsertIssueBatch(context.Background(), execer, result.Issues); err != nil {
		t.Fatalf("upsertIssueBatch() error = %v", err)
	}
	if err := store.upsertIssueFindingBatch(context.Background(), execer, result.IssueFindings); err != nil {
		t.Fatalf("upsertIssueFindingBatch() error = %v", err)
	}

	if got := len(execer.calls); got != 3 {
		t.Fatalf("ExecContext calls = %d, want 3", got)
	}

	if !strings.Contains(execer.calls[0].query, "($1, $2, $3, $4, $5, $6), ($7, $8, $9, $10, $11, $12)") {
		t.Fatalf("evaluation batch query missing multi-row values: %s", execer.calls[0].query)
	}
	if got := len(execer.calls[0].args); got != 12 {
		t.Fatalf("evaluation batch args = %d, want 12", got)
	}

	if !strings.Contains(execer.calls[1].query, "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20), ($21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40)") {
		t.Fatalf("issue batch query missing multi-row values: %s", execer.calls[1].query)
	}
	if got := len(execer.calls[1].args); got != 40 {
		t.Fatalf("issue batch args = %d, want 40", got)
	}

	if !strings.Contains(execer.calls[2].query, "($1, $2, $3), ($4, $5, $6)") {
		t.Fatalf("issue_finding batch query missing multi-row values: %s", execer.calls[2].query)
	}
	if got := len(execer.calls[2].args); got != 6 {
		t.Fatalf("issue_finding batch args = %d, want 6", got)
	}
}
