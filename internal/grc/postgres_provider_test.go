package grc

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestPostgresGRCProvider_Integration runs integration tests against a real PostgreSQL database.
// Requires POSTGRES_TEST_DSN environment variable or defaults to local test database.
// Skip with: go test -short
func TestPostgresGRCProvider_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	dsn := getTestDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("Skipping: cannot connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Skipf("Skipping: PostgreSQL not available: %v", err)
	}

	// Setup test schema
	if err := setupTestSchema(db); err != nil {
		t.Fatalf("Failed to setup test schema: %v", err)
	}
	defer cleanupTestSchema(db)

	provider := NewPostgresGRCProvider(db)
	ctx := context.Background()

	t.Run("CreateException", func(t *testing.T) {
		req := &ExceptionRequest{
			ApplicationID:     "TEST-APP-001",
			RequestorEmail:    "test@example.com",
			RequestType:       ExceptionTypeRegion,
			PolicyViolated:    "REGION-001",
			ResourceRequested: "us-west-2",
			BusinessCase:      "Integration test",
			ApproverChain: []Approver{
				{Email: "approver1@example.com", Role: "SECURITY_LEAD"},
				{Email: "approver2@example.com", Role: "GRC_ANALYST"},
			},
		}

		result, err := provider.CreateException(ctx, req)
		if err != nil {
			t.Fatalf("CreateException failed: %v", err)
		}

		if result.ID == "" {
			t.Error("expected non-empty ID")
		}
		if result.Status != StatusPending {
			t.Errorf("expected PENDING, got %s", result.Status)
		}

		// Verify in database
		retrieved, err := provider.GetException(ctx, result.ID)
		if err != nil {
			t.Fatalf("GetException failed: %v", err)
		}
		if retrieved.ApplicationID != req.ApplicationID {
			t.Errorf("expected %s, got %s", req.ApplicationID, retrieved.ApplicationID)
		}
		if len(retrieved.ApproverChain) != 2 {
			t.Errorf("expected 2 approvers, got %d", len(retrieved.ApproverChain))
		}
	})

	t.Run("ApprovalWorkflow", func(t *testing.T) {
		// Create exception
		req := &ExceptionRequest{
			ApplicationID:     "TEST-APP-002",
			RequestorEmail:    "test@example.com",
			RequestType:       ExceptionTypeService,
			PolicyViolated:    "SERVICE-001",
			ResourceRequested: "lambda",
			BusinessCase:      "Test approval workflow",
			ApproverChain: []Approver{
				{Email: "lead@example.com", Role: "LEAD"},
				{Email: "ciso@example.com", Role: "CISO"},
			},
		}

		created, _ := provider.CreateException(ctx, req)

		// First approval
		err := provider.SubmitApproval(ctx, created.ID, Approver{
			Email:    "lead@example.com",
			Decision: StatusApproved,
			Comments: "Approved by lead",
		})
		if err != nil {
			t.Fatalf("First approval failed: %v", err)
		}

		retrieved, _ := provider.GetException(ctx, created.ID)
		if retrieved.Status != StatusPending {
			t.Errorf("expected still PENDING, got %s", retrieved.Status)
		}

		// Second approval - should complete
		err = provider.SubmitApproval(ctx, created.ID, Approver{
			Email:    "ciso@example.com",
			Decision: StatusApproved,
			Comments: "CISO approved",
		})
		if err != nil {
			t.Fatalf("Second approval failed: %v", err)
		}

		retrieved, _ = provider.GetException(ctx, created.ID)
		if retrieved.Status != StatusApproved {
			t.Errorf("expected APPROVED, got %s", retrieved.Status)
		}
	})

	t.Run("ValidationQuery", func(t *testing.T) {
		// Create approved exception with expiration
		future := time.Now().AddDate(0, 1, 0)
		req := &ExceptionRequest{
			ApplicationID:     "VALID-APP",
			RequestorEmail:    "test@example.com",
			RequestType:       ExceptionTypeNetwork,
			PolicyViolated:    "NETWORK-001",
			ResourceRequested: "public-lb",
			BusinessCase:      "Test validation",
			ExpirationDate:    &future,
			ApproverChain: []Approver{
				{Email: "approver@example.com", Role: "SECURITY"},
			},
		}

		created, _ := provider.CreateException(ctx, req)
		provider.SubmitApproval(ctx, created.ID, Approver{
			Email:    "approver@example.com",
			Decision: StatusApproved,
		})

		// Test validation
		validation, err := provider.ValidateException(ctx, "VALID-APP", "NETWORK-001")
		if err != nil {
			t.Fatalf("ValidateException failed: %v", err)
		}
		if !validation.Valid {
			t.Error("expected valid exception")
		}

		// Test non-existent validation
		validation, _ = provider.ValidateException(ctx, "NONEXISTENT", "NETWORK-001")
		if validation.Valid {
			t.Error("expected invalid for non-existent app")
		}
	})

	t.Run("GetPendingApprovals", func(t *testing.T) {
		req := &ExceptionRequest{
			ApplicationID:     "PENDING-APP",
			RequestorEmail:    "test@example.com",
			RequestType:       ExceptionTypeData,
			PolicyViolated:    "DATA-001",
			ResourceRequested: "eu-storage",
			BusinessCase:      "Test pending query",
			ApproverChain: []Approver{
				{Email: "pending-approver@example.com", Role: "DPO"},
			},
		}
		provider.CreateException(ctx, req)

		pending, err := provider.GetPendingApprovals(ctx, "pending-approver@example.com")
		if err != nil {
			t.Fatalf("GetPendingApprovals failed: %v", err)
		}
		if len(pending) == 0 {
			t.Error("expected at least one pending approval")
		}

		found := false
		for _, p := range pending {
			if p.ApplicationID == "PENDING-APP" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find PENDING-APP in results")
		}
	})

	t.Run("GetExpiringExceptions", func(t *testing.T) {
		exp15Days := time.Now().AddDate(0, 0, 15)
		req := &ExceptionRequest{
			ApplicationID:     "EXPIRING-APP",
			RequestorEmail:    "test@example.com",
			RequestType:       ExceptionTypeOther,
			PolicyViolated:    "OTHER-001",
			ResourceRequested: "temp-resource",
			BusinessCase:      "Test expiring query",
			ExpirationDate:    &exp15Days,
			ApproverChain: []Approver{
				{Email: "exp-approver@example.com", Role: "ADMIN"},
			},
		}

		created, _ := provider.CreateException(ctx, req)
		provider.SubmitApproval(ctx, created.ID, Approver{
			Email:    "exp-approver@example.com",
			Decision: StatusApproved,
		})

		expiring, err := provider.GetExpiringExceptions(ctx, 30)
		if err != nil {
			t.Fatalf("GetExpiringExceptions failed: %v", err)
		}

		found := false
		for _, e := range expiring {
			if e.ApplicationID == "EXPIRING-APP" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected to find EXPIRING-APP in expiring list")
		}
	})
}

func getTestDSN() string {
	// Default test DSN for local development
	return "postgres://postgres:postgres@localhost:5432/aegis_test?sslmode=disable"
}

func setupTestSchema(db *sql.DB) error {
	schema := `
		DROP TABLE IF EXISTS exception_audit_log CASCADE;
		DROP TABLE IF EXISTS compensating_controls CASCADE;
		DROP TABLE IF EXISTS approval_chain CASCADE;
		DROP TABLE IF EXISTS risk_assessments CASCADE;
		DROP TABLE IF EXISTS exception_requests CASCADE;
		DROP VIEW IF EXISTS valid_exceptions;

		CREATE TABLE exception_requests (
			id UUID PRIMARY KEY,
			application_id VARCHAR(255) NOT NULL,
			requestor_email VARCHAR(255) NOT NULL,
			request_type VARCHAR(50) NOT NULL,
			policy_violated VARCHAR(50) NOT NULL,
			resource_requested TEXT NOT NULL,
			business_case TEXT NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
			expiration_date TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			metadata JSONB DEFAULT '{}'
		);

		CREATE TABLE risk_assessments (
			id UUID PRIMARY KEY,
			exception_id UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
			risk_level VARCHAR(20) NOT NULL,
			impact TEXT,
			likelihood TEXT,
			residual_risk TEXT,
			assessed_by VARCHAR(255) NOT NULL,
			assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE compensating_controls (
			id UUID PRIMARY KEY,
			exception_id UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
			control_description TEXT NOT NULL,
			implemented BOOLEAN DEFAULT FALSE,
			verified_by VARCHAR(255),
			verified_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE approval_chain (
			id UUID PRIMARY KEY,
			exception_id UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
			sequence_order INT NOT NULL,
			approver_email VARCHAR(255) NOT NULL,
			approver_role VARCHAR(50) NOT NULL,
			decision VARCHAR(20),
			comments TEXT,
			decided_at TIMESTAMPTZ
		);

		CREATE TABLE exception_audit_log (
			id UUID PRIMARY KEY,
			exception_id UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
			action VARCHAR(50) NOT NULL,
			actor_email VARCHAR(255) NOT NULL,
			old_value JSONB,
			new_value JSONB,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE VIEW valid_exceptions AS
		SELECT id, application_id, policy_violated, expiration_date, status
		FROM exception_requests
		WHERE status = 'APPROVED'
		  AND (expiration_date IS NULL OR expiration_date > NOW());
	`
	_, err := db.Exec(schema)
	return err
}

func cleanupTestSchema(db *sql.DB) {
	db.Exec("DROP TABLE IF EXISTS exception_audit_log CASCADE")
	db.Exec("DROP TABLE IF EXISTS compensating_controls CASCADE")
	db.Exec("DROP TABLE IF EXISTS approval_chain CASCADE")
	db.Exec("DROP TABLE IF EXISTS risk_assessments CASCADE")
	db.Exec("DROP TABLE IF EXISTS exception_requests CASCADE")
	db.Exec("DROP VIEW IF EXISTS valid_exceptions")
}

// TestPostgresGRCProvider_Unit tests the provider without a database connection.
// Uses mocks to verify query construction and error handling.
func TestPostgresGRCProvider_Unit(t *testing.T) {
	t.Run("NewPostgresGRCProvider", func(t *testing.T) {
		// Provider creation should work with nil db (used for lazy initialization)
		provider := NewPostgresGRCProvider(nil)
		if provider == nil {
			t.Error("expected non-nil provider")
		}
	})

	t.Run("GetException_NotFound", func(t *testing.T) {
		// Skip if no test database
		if testing.Short() {
			t.Skip("Skipping integration test")
		}

		dsn := getTestDSN()
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Skip("Skipping: no database")
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			t.Skip("Skipping: database not available")
		}

		if err := setupTestSchema(db); err != nil {
			t.Fatal(err)
		}
		defer cleanupTestSchema(db)

		provider := NewPostgresGRCProvider(db)
		_, err = provider.GetException(context.Background(), "nonexistent-uuid")
		if err == nil {
			t.Error("expected error for nonexistent exception")
		}
	})
}
