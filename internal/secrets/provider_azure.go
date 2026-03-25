package secrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"go.uber.org/zap"
)

// AzureKeyVaultProvider implements Provider for Azure Key Vault.
type AzureKeyVaultProvider struct {
	client   *azsecrets.Client
	vaultURL string
	logger   *zap.Logger
}

// NewAzureKeyVaultProvider creates a provider using DefaultAzureCredential.
// vaultURL format: https://<vault-name>.vault.azure.net
func NewAzureKeyVaultProvider(vaultURL string, logger *zap.Logger) *AzureKeyVaultProvider {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		logger.Error("Failed to create Azure credential for Key Vault", zap.Error(err))
		return &AzureKeyVaultProvider{vaultURL: vaultURL, logger: logger}
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		logger.Error("Failed to create Key Vault client", zap.Error(err))
		return &AzureKeyVaultProvider{vaultURL: vaultURL, logger: logger}
	}
	return &AzureKeyVaultProvider{
		client:   client,
		vaultURL: vaultURL,
		logger:   logger,
	}
}

func (p *AzureKeyVaultProvider) Name() string { return "azure" }

func (p *AzureKeyVaultProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	if p.client == nil {
		return nil, fmt.Errorf("azure key vault client not initialized")
	}
	resp, err := p.client.GetSecret(ctx, path, "", nil)
	if err != nil {
		return nil, fmt.Errorf("getting secret %q: %w", path, err)
	}

	s := &Secret{
		Path:     path,
		Metadata: make(map[string]string),
	}
	if resp.Value != nil {
		s.Value = []byte(*resp.Value)
	}
	if resp.ID != nil {
		s.Metadata["id"] = string(*resp.ID)
		parts := strings.Split(string(*resp.ID), "/")
		if len(parts) > 0 {
			s.Version = parts[len(parts)-1]
		}
	}
	if resp.Attributes != nil {
		if resp.Attributes.Created != nil {
			s.CreatedAt = *resp.Attributes.Created
		}
		if resp.Attributes.Updated != nil {
			s.UpdatedAt = *resp.Attributes.Updated
		}
		if resp.Attributes.Expires != nil {
			s.ExpiresAt = resp.Attributes.Expires
		}
	}
	return s, nil
}

func (p *AzureKeyVaultProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	if p.client == nil {
		return fmt.Errorf("azure key vault client not initialized")
	}
	v := string(value)
	_, err := p.client.SetSecret(ctx, path, azsecrets.SetSecretParameters{
		Value: &v,
	}, nil)
	if err != nil {
		return fmt.Errorf("setting secret %q: %w", path, err)
	}
	return nil
}

func (p *AzureKeyVaultProvider) DeleteSecret(ctx context.Context, path string) error {
	if p.client == nil {
		return fmt.Errorf("azure key vault client not initialized")
	}
	_, err := p.client.DeleteSecret(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("deleting secret %q: %w", path, err)
	}
	return nil
}

func (p *AzureKeyVaultProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	if p.client == nil {
		return nil, fmt.Errorf("azure key vault client not initialized")
	}
	var names []string
	pager := p.client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}
		for _, item := range page.Value {
			if item.ID == nil {
				continue
			}
			name := extractAzureSecretName(string(*item.ID))
			if prefix == "" || strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func (p *AzureKeyVaultProvider) RotateSecret(ctx context.Context, path string) error {
	// Azure Key Vault doesn't have a built-in rotate API like AWS.
	// Rotation is typically handled by creating a new version.
	if p.client == nil {
		return fmt.Errorf("azure key vault client not initialized")
	}
	// Read current, set new version (Azure auto-versions on SetSecret).
	current, err := p.GetSecret(ctx, path)
	if err != nil {
		return fmt.Errorf("reading current secret for rotation: %w", err)
	}
	_ = current // Caller should generate new value and call SetSecret
	return fmt.Errorf("azure key vault rotation requires caller to provide new value via SetSecret (auto-versioned)")
}

// extractAzureSecretName extracts the secret name from a Key Vault secret ID URL.
// Format: https://<vault>.vault.azure.net/secrets/<name>/<version>
func extractAzureSecretName(id string) string {
	parts := strings.Split(id, "/secrets/")
	if len(parts) < 2 {
		return id
	}
	name := parts[1]
	if idx := strings.Index(name, "/"); idx >= 0 {
		name = name[:idx]
	}
	return name
}

// azureExpiresAt converts a duration to an Azure-compatible expiry time pointer.
func azureExpiresAt(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
}
