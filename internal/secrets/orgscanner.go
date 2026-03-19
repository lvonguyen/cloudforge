package secrets

import "context"

// OrgScanner scans multiple repositories in an organisation for leaked secrets.
type OrgScanner interface {
	ScanOrg(ctx context.Context, cfg OrgConfig) (*OrgScanResult, error)
}

// OrgConfig is the input for an org-wide secrets scan.
type OrgConfig struct {
	OrgName    string   `json:"org_name"`
	Repos      []string `json:"repos,omitempty"`      // Empty = all repos
	MaxWorkers int      `json:"max_workers,omitempty"` // Parallelism (default 5)
}

// OrgScanResult is the output of an org-wide secrets scan.
type OrgScanResult struct {
	OrgName      string          `json:"org_name"`
	ReposScanned int             `json:"repos_scanned"`
	TotalSecrets int             `json:"total_secrets"`
	Results      []RepoResult    `json:"results"`
	Errors       []ScanRepoError `json:"errors,omitempty"`
}

// RepoResult contains findings for a single repository.
type RepoResult struct {
	Repo     string          `json:"repo"`
	Findings []SecretFinding `json:"findings"`
}

// ScanRepoError records a per-repo scan failure.
type ScanRepoError struct {
	Repo    string `json:"repo"`
	Message string `json:"message"`
}
