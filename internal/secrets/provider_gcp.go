package secrets

import (
	"context"
	"fmt"
	"strings"

	gcpsm "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
)

// GCPSecretManagerProvider implements Provider for GCP Secret Manager.
type GCPSecretManagerProvider struct {
	client    *gcpsm.Client
	projectID string
	logger    *zap.Logger
}

// NewGCPSecretManagerProvider creates a provider using Application Default Credentials.
func NewGCPSecretManagerProvider(projectID string, logger *zap.Logger) *GCPSecretManagerProvider {
	client, err := gcpsm.NewClient(context.Background())
	if err != nil {
		logger.Error("Failed to create GCP Secret Manager client", zap.Error(err))
		return &GCPSecretManagerProvider{projectID: projectID, logger: logger}
	}
	return &GCPSecretManagerProvider{
		client:    client,
		projectID: projectID,
		logger:    logger,
	}
}

func (p *GCPSecretManagerProvider) Name() string { return "gcp" }

func (p *GCPSecretManagerProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	if p.client == nil {
		return nil, fmt.Errorf("gcp secret manager client not initialized")
	}
	name := p.secretVersionName(path, "latest")
	resp, err := p.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("accessing secret %q: %w", path, err)
	}

	s := &Secret{
		Path:     path,
		Value:    resp.Payload.Data,
		Metadata: make(map[string]string),
	}
	s.Metadata["name"] = resp.Name

	// Fetch metadata (create time, etc.)
	meta, err := p.client.GetSecretVersion(ctx, &secretmanagerpb.GetSecretVersionRequest{
		Name: name,
	})
	if err == nil && meta.CreateTime != nil {
		s.CreatedAt = meta.CreateTime.AsTime()
		s.UpdatedAt = meta.CreateTime.AsTime()
		s.Version = extractGCPVersion(meta.Name)
	}

	return s, nil
}

func (p *GCPSecretManagerProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	if p.client == nil {
		return fmt.Errorf("gcp secret manager client not initialized")
	}
	parent := fmt.Sprintf("projects/%s", p.projectID)
	secretName := fmt.Sprintf("%s/secrets/%s", parent, path)

	// Try to add a version (secret exists).
	_, err := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  secretName,
		Payload: &secretmanagerpb.SecretPayload{Data: value},
	})
	if err != nil {
		// Secret may not exist — create it first.
		_, createErr := p.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   parent,
			SecretId: path,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{
						Automatic: &secretmanagerpb.Replication_Automatic{},
					},
				},
			},
		})
		if createErr != nil {
			return fmt.Errorf("creating secret %q: %w (add version: %v)", path, createErr, err)
		}
		// Now add the version.
		_, err = p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent:  secretName,
			Payload: &secretmanagerpb.SecretPayload{Data: value},
		})
		if err != nil {
			return fmt.Errorf("adding version to %q: %w", path, err)
		}
	}
	return nil
}

func (p *GCPSecretManagerProvider) DeleteSecret(ctx context.Context, path string) error {
	if p.client == nil {
		return fmt.Errorf("gcp secret manager client not initialized")
	}
	name := fmt.Sprintf("projects/%s/secrets/%s", p.projectID, path)
	err := p.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("deleting secret %q: %w", path, err)
	}
	return nil
}

func (p *GCPSecretManagerProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	if p.client == nil {
		return nil, fmt.Errorf("gcp secret manager client not initialized")
	}
	parent := fmt.Sprintf("projects/%s", p.projectID)
	var names []string

	it := p.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: parent,
	})
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}
		name := extractGCPSecretName(s.Name)
		if prefix == "" || strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

func (p *GCPSecretManagerProvider) RotateSecret(ctx context.Context, path string) error {
	// GCP Secret Manager doesn't have a built-in rotate API.
	// Rotation is handled by adding a new version via SetSecret.
	return fmt.Errorf("gcp secret manager rotation requires caller to provide new value via SetSecret (auto-versioned)")
}

// secretVersionName builds the full resource name for a secret version.
func (p *GCPSecretManagerProvider) secretVersionName(secretID, version string) string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", p.projectID, secretID, version)
}

// extractGCPSecretName extracts the secret ID from a full resource name.
// Format: projects/{project}/secrets/{secret}
func extractGCPSecretName(fullName string) string {
	parts := strings.Split(fullName, "/secrets/")
	if len(parts) < 2 {
		return fullName
	}
	return parts[1]
}

// extractGCPVersion extracts the version number from a version resource name.
// Format: projects/{project}/secrets/{secret}/versions/{version}
func extractGCPVersion(fullName string) string {
	parts := strings.Split(fullName, "/versions/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
