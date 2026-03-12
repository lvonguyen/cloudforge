package grc

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

// ArcherConfig contains configuration for RSA Archer GRC integration.
// Credentials are loaded from environment variables for security.
type ArcherConfig struct {
	BaseURL      string
	InstanceName string
	Username     string

	// PasswordEnv is the name of the environment variable containing the password.
	// The actual password is never stored in the struct.
	PasswordEnv string

	ModuleID int // Archer module/application ID for exceptions
}

// ArcherGRCProvider implements GRCProvider for RSA Archer.
// RSA Archer is an enterprise GRC platform commonly used for policy exception
// management in large organizations.
//
// Note: Archer's API uses numeric field IDs rather than field names, which
// makes integration more complex. Field IDs vary by Archer implementation
// and must be configured per deployment.
type ArcherGRCProvider struct {
	config     ArcherConfig
	httpClient *http.Client
	password string // loaded from env at initialization
}

// NewArcherGRCProvider creates a new RSA Archer GRC provider.
// Returns an error if required credentials are missing from environment variables.
func NewArcherGRCProvider(config ArcherConfig) (*ArcherGRCProvider, error) {
	// Validate required fields
	if config.BaseURL == "" {
		return nil, fmt.Errorf("creating Archer provider: BaseURL is required")
	}
	if config.Username == "" {
		return nil, fmt.Errorf("creating Archer provider: Username is required")
	}

	// Load password from environment
	if config.PasswordEnv == "" {
		return nil, fmt.Errorf("creating Archer provider: PasswordEnv must be specified")
	}
	password := os.Getenv(config.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("creating Archer provider: password environment variable %s is not set", config.PasswordEnv)
	}

	return &ArcherGRCProvider{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		password:   password,
	}, nil
}

// newArcherProviderForTest creates an Archer provider for testing,
// bypassing env-var loading. Unexported — test-only.
func newArcherProviderForTest() *ArcherGRCProvider {
	return &ArcherGRCProvider{
		config: ArcherConfig{
			BaseURL:      "https://archer.test",
			InstanceName: "test",
			Username:     "test",
		},
		httpClient: &http.Client{},
		password:   "test",
	}
}

// CreateException creates a new exception request in Archer.
func (a *ArcherGRCProvider) CreateException(
	ctx context.Context,
	req *ExceptionRequest,
) (*ExceptionRequest, error) {
	// Map internal model to Archer's field IDs
	// Archer uses numeric field IDs, not names 🙃
	// These field IDs would need to be configured per Archer instance
	//
	// archerRecord := map[string]interface{}{
	//     "FieldContents": map[string]interface{}{
	//         "12345": req.ApplicationID,     // "Application ID" field
	//         "12346": req.RequestorEmail,    // "Requestor" field
	//         "12347": req.BusinessCase,      // "Business Justification" field
	//         "12348": req.ResourceRequested, // "Requested Resource" field
	//     },
	// }
	//
	// POST to Archer API: /api/core/content/
	//
	// See RSA Archer REST API documentation:
	// https://community.rsa.com/t5/archer-documentation/archer-rest-api-guide/ta-p/569842

	return nil, fmt.Errorf("archer integration requires instance-specific field mapping configuration")
}

// GetException retrieves an exception from Archer by content ID.
func (a *ArcherGRCProvider) GetException(ctx context.Context, id string) (*ExceptionRequest, error) {
	// GET /api/core/content/{contentId}
	return nil, fmt.Errorf("archer GetException not implemented")
}

// UpdateException updates an exception record in Archer.
func (a *ArcherGRCProvider) UpdateException(ctx context.Context, req *ExceptionRequest) error {
	// PUT /api/core/content/{contentId}
	return fmt.Errorf("archer UpdateException not implemented")
}

// ValidateException checks if a valid exception exists in Archer.
func (a *ArcherGRCProvider) ValidateException(
	ctx context.Context,
	applicationID, policyCode string,
) (*ExceptionValidation, error) {
	// Would use Archer's search API to find matching exception records
	// POST /api/core/search
	// with a search filter for application ID, policy code, and status
	return nil, fmt.Errorf("archer ValidateException not implemented")
}

// SubmitApproval records an approval decision in Archer.
func (a *ArcherGRCProvider) SubmitApproval(ctx context.Context, exceptionID string, approver Approver) error {
	// Archer has a workflow engine for approvals
	// This would update the workflow state
	return fmt.Errorf("archer SubmitApproval not implemented")
}

// GetPendingApprovals returns exceptions awaiting approval from the given user.
func (a *ArcherGRCProvider) GetPendingApprovals(ctx context.Context, approverEmail string) ([]ExceptionRequest, error) {
	// Search for workflow tasks assigned to the approver
	return nil, fmt.Errorf("archer GetPendingApprovals not implemented")
}

// GetExceptionsByApplication returns all exceptions for an application.
func (a *ArcherGRCProvider) GetExceptionsByApplication(ctx context.Context, appID string) ([]ExceptionRequest, error) {
	// POST /api/core/search with application ID filter
	return nil, fmt.Errorf("archer GetExceptionsByApplication not implemented")
}

// GetExpiringExceptions returns exceptions expiring within the given days.
func (a *ArcherGRCProvider) GetExpiringExceptions(ctx context.Context, withinDays int) ([]ExceptionRequest, error) {
	// POST /api/core/search with date range filter on expiration field
	return nil, fmt.Errorf("archer GetExpiringExceptions not implemented")
}

// GetExceptionsByRequestor returns all exceptions created by the given user.
func (a *ArcherGRCProvider) GetExceptionsByRequestor(ctx context.Context, email string) ([]ExceptionRequest, error) {
	// POST /api/core/search with requestor email filter
	return nil, fmt.Errorf("archer GetExceptionsByRequestor not implemented")
}
