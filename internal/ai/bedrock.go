package ai

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

const (
	// BedrockModelSonnet is the fast-tier Claude model on Bedrock (cross-region inference profile).
	BedrockModelSonnet = "us.anthropic.claude-sonnet-4-6"
	// BedrockModelOpus is the premium-tier Claude model on Bedrock (cross-region inference profile).
	BedrockModelOpus = "us.anthropic.claude-opus-4-6-v1"
)

// bedrockInvoker abstracts the Bedrock InvokeModel call for testability.
type bedrockInvoker interface {
	InvokeModel(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

// BedrockProvider implements Provider using AWS Bedrock with Claude models.
type BedrockProvider struct {
	client  bedrockInvoker
	modelID string
	region  string
}

// NewBedrockProvider creates a BedrockProvider using the DefaultCredentialChain for the given region.
func NewBedrockProvider(region, modelID string) (*BedrockProvider, error) {
	if region == "" {
		region = "us-east-1"
	}
	if modelID == "" {
		modelID = BedrockModelSonnet
	}

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for bedrock: %w", err)
	}

	return &BedrockProvider{
		client:  bedrockruntime.NewFromConfig(cfg),
		modelID: modelID,
		region:  region,
	}, nil
}

// ModelID returns the Bedrock model identifier in use.
func (p *BedrockProvider) ModelID() string {
	return p.modelID
}

// Complete sends a single-turn prompt to Bedrock.
func (p *BedrockProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return p.CompleteWithSystem(ctx, "", prompt)
}

// CompleteWithSystem sends a system + user prompt pair to Bedrock via InvokeModel.
func (p *BedrockProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     p.modelID,
		MaxTokens: 4096,
		Messages: []message{
			{Role: "user", Content: userPrompt},
		},
	}
	if systemPrompt != "" {
		reqBody.System = systemPrompt
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshaling bedrock request: %w", err)
	}

	out, err := p.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(p.modelID),
		Body:        body,
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
	})
	if err != nil {
		return "", fmt.Errorf("bedrock InvokeModel: %w", err)
	}

	var resp anthropicResponse
	if err := json.Unmarshal(out.Body, &resp); err != nil {
		return "", fmt.Errorf("decoding bedrock response: %w", err)
	}

	if resp.Error != nil {
		return "", fmt.Errorf("bedrock API error: %s", resp.Error.Message)
	}

	if len(resp.Content) == 0 {
		return "", fmt.Errorf("empty response from bedrock")
	}

	return resp.Content[0].Text, nil
}

// newBedrockProviderForTest creates a BedrockProvider with a custom client for testing.
func newBedrockProviderForTest(client bedrockInvoker, modelID string) *BedrockProvider {
	return &BedrockProvider{
		client:  client,
		modelID: modelID,
		region:  "us-east-1",
	}
}
