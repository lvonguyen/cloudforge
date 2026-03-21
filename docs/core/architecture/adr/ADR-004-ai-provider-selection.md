# ADR-004: AI Provider Selection

## Status

Accepted

## Date

2026-01-05

## Context

AI capabilities are required for:
- Contextual risk scoring beyond static severity
- Toxic combination detection across findings
- Natural language remediation recommendations
- Misconfiguration root cause analysis

### Options Considered

1. **Anthropic Claude Opus 4.6** - Large context, strong reasoning
2. **OpenAI GPT-4 Turbo** - Fast, cost-effective, proven
3. **Self-hosted LLM (Llama)** - Privacy, no API costs
4. **AWS Bedrock** - Managed, multiple models

## Decision

**Anthropic Claude Opus 4.6** was selected as primary, with **OpenAI GPT-4** as fallback.

## Rationale

### Claude Opus 4.6 Primary

| Factor | Reasoning |
|--------|-----------|
| Context Window | 200K tokens - can analyze 50+ findings at once |
| Reasoning | Superior for nuanced security analysis |
| Structured Output | More consistent JSON generation |
| Hallucination | More conservative in risk assessment |

### GPT-4 Fallback

| Factor | Reasoning |
|--------|-----------|
| Rate Limits | Higher throughput when Claude is limited |
| Cost | 60% cheaper for output-heavy workloads |
| Availability | Different failure domain |

### Why Not Self-Hosted

- Requires significant GPU infrastructure
- Model quality gap for complex reasoning
- Maintenance and update burden
- Security review of model weights

## Implementation

### Request Routing

```
if request.requires_deep_analysis:
    provider = "claude-opus-4-6"
elif request.high_volume:
    provider = "gpt-4-turbo"
else:
    provider = "claude-opus-4-6"
```

### Cost Optimization

- Cache AI responses for similar findings (30% reduction)
- Batch findings for context efficiency
- Use cheaper models for simple enrichment

### Fallback Logic

```
try:
    response = claude.analyze(finding)
except RateLimitError:
    response = openai.analyze(finding)
except APIError:
    response = static_analysis(finding)  # Graceful degradation
```

## Consequences

### Positive
- Best-in-class reasoning for security analysis
- Large context enables batch processing
- Fallback ensures availability

### Negative
- ~$2,600/month for 100K findings
- External API dependency
- Data leaves infrastructure

### Mitigations
- Implement response caching
- Use batch processing for efficiency
- Encrypt findings before sending
- Implement circuit breaker for outages

## Cost Estimate

| Volume | Claude Only | Hybrid | Savings |
|--------|-------------|--------|---------|
| 10K/mo | $260 | $200 | 23% |
| 100K/mo | $2,600 | $1,800 | 31% |
| 1M/mo | $26,000 | $18,000 | 31% |

## Update: AWS Bedrock as Production Enrichment Provider

**Date:** 2026-03-20

For production enrichment workloads (finding risk scoring, remediation recommendations), Cloud Aegis uses **AWS Bedrock** (`anthropic.claude-haiku-4-5-20251001-v1:0`) as the managed inference provider. Bedrock eliminates the need to manage API keys for direct Anthropic/OpenAI access in production, uses IAM-based authentication (see `bedrock-sa` IAM user), and keeps inference traffic within the AWS network boundary.

The provider abstraction (`AIProvider` interface) remains unchanged -- Bedrock is configured via `PLATFORM_PROVIDER=bedrock` and `BEDROCK_ENABLED=true` environment variables. The fallback chain is: Bedrock -> direct Anthropic API -> static analysis.

Direct Anthropic Claude Opus 4.6 and OpenAI GPT-4 remain available for local development and as fallback providers.

## Related Decisions

- ADR-005: Rate Limiting Strategy
- ADR-018: Threat Intelligence Feed Integration

