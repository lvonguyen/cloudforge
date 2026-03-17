package finops

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"go.uber.org/zap"
)

// AWSAggregator fetches real cost data from AWS Cost Explorer.
type AWSAggregator struct {
	client *costexplorer.Client
	logger *zap.Logger
}

// NewAWSAggregator creates an aggregator backed by AWS Cost Explorer.
// Credentials are resolved via the standard AWS chain (env vars, SSO profile, IMDS).
func NewAWSAggregator(region string, logger *zap.Logger) (*AWSAggregator, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &AWSAggregator{
		client: costexplorer.NewFromConfig(cfg),
		logger: logger,
	}, nil
}

// FetchCosts queries AWS Cost Explorer for daily cost grouped by SERVICE and LINKED_ACCOUNT.
func (a *AWSAggregator) FetchCosts(ctx context.Context, start, end time.Time) ([]CostRecord, error) {
	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: aws.String(start.Format("2006-01-02")),
			End:   aws.String(end.Format("2006-01-02")),
		},
		Granularity: cetypes.GranularityDaily,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("SERVICE")},
			{Type: cetypes.GroupDefinitionTypeDimension, Key: aws.String("LINKED_ACCOUNT")},
		},
	}

	var records []CostRecord
	id := 0

	for {
		out, err := a.client.GetCostAndUsage(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("GetCostAndUsage: %w", err)
		}

		for _, result := range out.ResultsByTime {
			date, _ := time.Parse("2006-01-02", aws.ToString(result.TimePeriod.Start))

			for _, group := range result.Groups {
				var svc, acct string
				if len(group.Keys) > 0 {
					svc = group.Keys[0]
				}
				if len(group.Keys) > 1 {
					acct = group.Keys[1]
				}

				amount := 0.0
				if m, ok := group.Metrics["UnblendedCost"]; ok {
					amount, _ = strconv.ParseFloat(aws.ToString(m.Amount), 64)
				}
				if amount == 0 {
					continue
				}

				id++
				records = append(records, CostRecord{
					ID:          fmt.Sprintf("aws-ce-%d", id),
					Provider:    "aws",
					AccountID:   acct,
					ServiceName: svc,
					Region:      "global",
					Date:        date,
					Cost:        amount,
					Currency:    "USD",
				})
			}
		}

		if out.NextPageToken == nil {
			break
		}
		input.NextPageToken = out.NextPageToken
	}

	a.logger.Info("Fetched AWS cost data",
		zap.Int("records", len(records)),
		zap.String("start", start.Format("2006-01-02")),
		zap.String("end", end.Format("2006-01-02")),
	)

	return records, nil
}

// NormalizeCosts for AWS is a no-op — Cost Explorer returns USD by default.
func (a *AWSAggregator) NormalizeCosts(records []CostRecord) []CostRecord {
	return records
}
