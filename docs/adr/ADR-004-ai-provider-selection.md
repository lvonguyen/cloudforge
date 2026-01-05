# ADR-004: AI Provider Selection

## Status

Accepted

## Date

2026-01-05

## Context

We need AI capabilities for:
- Contextual risk scoring beyond static severity
- Toxic combination detection across findings
- Natural language remediation recommendations
- Misconfiguration root cause analysis

### Options Considered

1. **Anthropic Claude Opus 4.5** - Large context, strong reasoning
2. **OpenAI GPT-4 Turbo** - Fast, cost-effective, proven
3. **Self-hosted LLM (Llama)** - Privacy, no API costs
4. **AWS Bedrock** - Managed, multiple models

## Decision

We will use **Anthropic Claude Opus 4.5** as primary, with **OpenAI GPT-4** as fallback.

## Rationale

### Claude Opus 4.5 Primary

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
    provider = "claude-opus-4.5"
elif request.high_volume:
    provider = "gpt-4-turbo"
else:
    provider = "claude-opus-4.5"
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

## Related Decisions

- ADR-005: Data Privacy Controls
- ADR-007: Error Handling Strategy

