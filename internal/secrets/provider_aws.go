package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"go.uber.org/zap"
)

// AWSSecretsProvider implements Provider for AWS Secrets Manager.
type AWSSecretsProvider struct {
	client *secretsmanager.Client
	region string
	logger *zap.Logger
}

// NewAWSSecretsProvider creates a provider using the default AWS credential chain.
func NewAWSSecretsProvider(region string, logger *zap.Logger) *AWSSecretsProvider {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
	if err != nil {
		logger.Error("Failed to load AWS config for Secrets Manager", zap.Error(err))
		return &AWSSecretsProvider{region: region, logger: logger}
	}
	return &AWSSecretsProvider{
		client: secretsmanager.NewFromConfig(cfg),
		region: region,
		logger: logger,
	}
}

func (p *AWSSecretsProvider) Name() string { return "aws" }

func (p *AWSSecretsProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	if p.client == nil {
		return nil, fmt.Errorf("aws secrets manager client not initialized")
	}
	out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	})
	if err != nil {
		return nil, fmt.Errorf("getting secret %q: %w", path, err)
	}

	var value []byte
	if out.SecretString != nil {
		value = []byte(*out.SecretString)
	} else {
		value = out.SecretBinary
	}

	s := &Secret{
		Path:     path,
		Value:    value,
		Metadata: make(map[string]string),
	}
	if out.VersionId != nil {
		s.Version = *out.VersionId
	}
	if out.CreatedDate != nil {
		s.CreatedAt = *out.CreatedDate
		s.UpdatedAt = *out.CreatedDate
	}
	if out.ARN != nil {
		s.Metadata["arn"] = *out.ARN
	}
	return s, nil
}

func (p *AWSSecretsProvider) SetSecret(ctx context.Context, path string, value []byte) error {
	if p.client == nil {
		return fmt.Errorf("aws secrets manager client not initialized")
	}
	_, err := p.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(path),
		SecretString: aws.String(string(value)),
	})
	if err != nil {
		_, createErr := p.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(path),
			SecretString: aws.String(string(value)),
		})
		if createErr != nil {
			return fmt.Errorf("creating secret %q: %w (put: %v)", path, createErr, err)
		}
	}
	return nil
}

func (p *AWSSecretsProvider) DeleteSecret(ctx context.Context, path string) error {
	if p.client == nil {
		return fmt.Errorf("aws secrets manager client not initialized")
	}
	_, err := p.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:             aws.String(path),
		RecoveryWindowInDays: aws.Int64(7),
	})
	if err != nil {
		return fmt.Errorf("deleting secret %q: %w", path, err)
	}
	return nil
}

func (p *AWSSecretsProvider) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	if p.client == nil {
		return nil, fmt.Errorf("aws secrets manager client not initialized")
	}
	var names []string
	var nextToken *string
	for {
		input := &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(100),
			NextToken:  nextToken,
		}
		if prefix != "" {
			input.Filters = []smtypes.Filter{
				{Key: smtypes.FilterNameStringTypeName, Values: []string{prefix}},
			}
		}
		out, err := p.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}
		for _, s := range out.SecretList {
			if s.Name != nil {
				names = append(names, *s.Name)
			}
		}
		nextToken = out.NextToken
		if nextToken == nil {
			break
		}
	}
	return names, nil
}

func (p *AWSSecretsProvider) RotateSecret(ctx context.Context, path string) error {
	if p.client == nil {
		return fmt.Errorf("aws secrets manager client not initialized")
	}
	_, err := p.client.RotateSecret(ctx, &secretsmanager.RotateSecretInput{
		SecretId: aws.String(path),
	})
	if err != nil {
		return fmt.Errorf("rotating secret %q: %w", path, err)
	}
	return nil
}
