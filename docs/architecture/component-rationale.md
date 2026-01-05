# Component Selection Rationale and Cost Analysis

| Document | Value |
| --- | --- |
| Version | 1.0 |
| Author | Liem Vo-Nguyen |
| Date | January 2026 |
| Project | CloudForge |

---

## 1. Cache Layer: Redis vs Memcached

### Decision: Redis

| Criteria | Redis | Memcached |
| --- | --- | --- |
| Data Structures | Rich (strings, hashes, lists, sets, sorted sets) | Simple key-value only |
| Persistence | Optional (RDB/AOF) | None |
| Replication | Built-in master-replica | Manual |
| Pub/Sub | Yes | No |
| Lua Scripting | Yes | No |
| Cluster Mode | Yes | No (client-side sharding) |
| Memory Efficiency | Moderate | High |

### Why Redis

1. **Session Management**: Need TTL with complex session objects
2. **Rate Limiting**: Atomic increment with expire (INCR + EXPIRE)
3. **Pub/Sub**: Real-time finding notifications
4. **Caching Compliance Data**: Hash structures for framework controls
5. **Distributed Locks**: Redlock for workflow coordination

### Cost Analysis (AWS ElastiCache)

| Workload | Redis | Memcached |
| --- | --- | --- |
| Instance | cache.r6g.large | cache.r6g.large |
| Monthly (On-Demand) | $219.60 | $175.20 |
| Monthly (Reserved 1yr) | $142.35 | $113.88 |
| Estimated Usage | 50GB cache, 10K ops/sec | 50GB cache, 10K ops/sec |

**Verdict**: Redis costs ~25% more but provides essential features (persistence, pub/sub, Lua) that would require custom implementation with Memcached.

---

## 2. Compute: Lambda vs EC2 vs EKS

### Decision: EKS (Primary), Lambda (Event Processing)

| Criteria | Lambda | EC2 | EKS |
| --- | --- | --- | --- |
| Cold Start | 100ms-10s | None | None |
| Max Duration | 15 min | Unlimited | Unlimited |
| Scaling | Automatic | Manual/ASG | HPA/KEDA |
| Cost Model | Per invocation | Per hour | Per hour + control plane |
| Ops Overhead | Low | High | Medium |
| State | Stateless | Stateful | Stateful pods |

### Why EKS (Primary)

1. **Long-Running Workflows**: Compliance scans can take hours
2. **Consistent Latency**: No cold starts for API requests
3. **Multi-Tenancy**: Namespace isolation for customers
4. **Sidecar Patterns**: Envoy for mTLS, Fluentd for logging
5. **Stateful Workloads**: Temporal workers need persistent connections

### Why Lambda (Event Processing)

1. **Webhook Receivers**: Sporadic GRC callbacks
2. **Scheduled Tasks**: Daily compliance reports
3. **Event-Driven**: S3 trigger for file processing

### Cost Analysis (100 concurrent users, 1M API calls/month)

| Component | Lambda | EC2 (m6i.large) | EKS (m6i.large) |
| --- | --- | --- | --- |
| Compute/month | $200 (invocations) | $138 (2 instances) | $138 + $73 (control plane) |
| Load Balancer | N/A | $22 | $22 (ingress) |
| Data Transfer | $10 | $50 | $50 |
| **Total** | **$210** | **$210** | **$283** |

**At Scale (10x)**

| Component | Lambda | EC2 | EKS |
| --- | --- | --- | --- |
| 10M calls/month | $2,000 | $690 (5 inst) | $690 + $73 |
| Scaling | Automatic | ASG lag | KEDA fast |

**Verdict**: EKS for API and long-running workloads ($73/mo premium for orchestration). Lambda for event-driven processing where cold starts acceptable.

---

## 3. Database: PostgreSQL vs MySQL vs DynamoDB

### Decision: PostgreSQL (Primary), DynamoDB (High-Scale Findings)

| Criteria | PostgreSQL | MySQL | DynamoDB |
| --- | --- | --- | --- |
| JSONB Support | Excellent | JSON (less performant) | Native |
| Partitioning | Built-in | Manual | Automatic |
| Extensions | Rich (pg_trgm, pgvector) | Limited | None |
| Transactions | Full ACID | Full ACID | Limited |
| Geospatial | PostGIS | Limited | Limited |
| Full-Text Search | Built-in | Built-in | OpenSearch needed |
| Cost (RDS) | Similar | Similar | Higher at scale |

### Why PostgreSQL

1. **JSONB for Findings**: Flexible schema for multi-source findings
2. **Array Types**: Compliance framework mappings as arrays
3. **pg_trgm**: Fuzzy search on finding descriptions
4. **CTEs**: Complex compliance reporting queries
5. **Partitioning**: By date for finding history

### Why DynamoDB (Adjunct)

1. **High-Volume Findings**: 100K+ findings/day ingestion
2. **Single-Table Design**: Finding lookup by ID
3. **TTL**: Automatic expiration of transient data
4. **Global Tables**: Multi-region replication

### Cost Analysis (500GB data, 10K reads/sec, 1K writes/sec)

| Component | PostgreSQL (RDS) | DynamoDB |
| --- | --- | --- |
| Instance | db.r6g.large | N/A |
| Storage (500GB) | $57.50 | $125 (standard) |
| Compute | $219.60 | N/A |
| Read Capacity | Included | $500 (on-demand) |
| Write Capacity | Included | $625 (on-demand) |
| **Monthly Total** | **$277** | **$1,250** |

**Verdict**: PostgreSQL for primary data store. DynamoDB only if needing multi-region active-active or >100K TPS.

---

## 4. Message Queue: SQS vs Kafka vs RabbitMQ

### Decision: SQS (Primary), Kafka (High-Volume Streams)

| Criteria | SQS | Kafka | RabbitMQ |
| --- | --- | --- | --- |
| Ordering | FIFO queues | Per-partition | Per-queue |
| Throughput | 3K msg/sec FIFO, unlimited std | 100K+ msg/sec | 50K msg/sec |
| Retention | 14 days | Configurable | Until consumed |
| Ops Overhead | None (managed) | High | Medium |
| Consumer Groups | No (fan-out via SNS) | Yes | Yes |
| Replay | No | Yes | No |

### Why SQS

1. **Managed**: Zero ops for queue infrastructure
2. **Integration**: Native Lambda, ECS triggers
3. **Dead Letter Queues**: Built-in DLQ support
4. **Sufficient Throughput**: 3K/sec FIFO covers most use cases

### Why Kafka (When Needed)

1. **Event Sourcing**: Full history replay capability
2. **High Volume**: >10K events/sec sustained
3. **Stream Processing**: Kafka Streams/ksqlDB
4. **Multi-Consumer**: Same events to multiple consumers

### Cost Analysis (1M messages/day)

| Component | SQS | MSK (Kafka) | AmazonMQ (RabbitMQ) |
| --- | --- | --- | --- |
| Messages | $12.60 | N/A | N/A |
| Broker Costs | N/A | $438 (2x kafka.m5.large) | $213 (mq.m5.large) |
| Storage | N/A | $30 (100GB) | Included |
| **Monthly Total** | **$13** | **$468** | **$213** |

**Verdict**: SQS for 99% of use cases. Kafka only for event sourcing requirements.

---

## 5. Orchestration: Temporal vs Step Functions vs Airflow

### Decision: Temporal

| Criteria | Temporal | Step Functions | Airflow |
| --- | --- | --- | --- |
| Long-Running | Unlimited | 1 year max | DAG-based |
| Code-Based Workflows | Yes (Go, Java, etc.) | JSON/YAML | Python |
| Retries | Sophisticated | Basic | Basic |
| Visibility | Excellent UI | CloudWatch | Good UI |
| Testing | Unit testable | Difficult | Moderate |
| Cost | Self-hosted | Per transition | Self-hosted |

### Why Temporal

1. **Code-Based**: Workflows as Go code, testable
2. **Long-Running**: Approval workflows can take weeks
3. **Saga Pattern**: Complex multi-step provisioning
4. **Visibility**: Built-in workflow history
5. **Self-Healing**: Automatic retry with backoff

### Cost Analysis

| Component | Temporal (Self-Hosted) | Step Functions |
| --- | --- | --- |
| Compute | 2x m6i.large = $138/mo | N/A |
| Transitions (1M/mo) | N/A | $25 |
| Storage | 50GB EBS = $5/mo | Included |
| **Monthly Total** | **$143** | **$25** |

**But**: Step Functions has state transition limits, no local testing, and JSON-based workflows. Temporal's code-first approach worth the cost for complex workflows.

---

## 6. AI Provider: Anthropic Claude vs OpenAI GPT-4

### Decision: Anthropic Claude Opus 4.5 (Primary), OpenAI GPT-4 (Fallback)

| Criteria | Claude Opus 4.5 | GPT-4 Turbo |
| --- | --- | --- |
| Context Window | 200K tokens | 128K tokens |
| Speed | Moderate | Fast |
| Reasoning | Excellent | Excellent |
| Coding | Excellent | Excellent |
| Cost (Input) | $15/1M tokens | $10/1M tokens |
| Cost (Output) | $75/1M tokens | $30/1M tokens |
| Rate Limits | Lower | Higher |

### Why Claude Opus 4.5 (Primary)

1. **Context Window**: 200K tokens for large finding batches
2. **Reasoning**: Better at nuanced security analysis
3. **Structured Output**: More consistent JSON responses
4. **Less Hallucination**: More conservative in risk assessment

### Why GPT-4 (Fallback)

1. **Rate Limits**: Higher throughput when needed
2. **Cost**: 60% cheaper for output-heavy workloads
3. **Availability**: Different failure domains

### Cost Analysis (100K findings/month, ~500 tokens/finding)

| Metric | Claude Opus 4.5 | GPT-4 Turbo |
| --- | --- | --- |
| Input Tokens | 50M @ $15/M = $750 | 50M @ $10/M = $500 |
| Output Tokens | 25M @ $75/M = $1,875 | 25M @ $30/M = $750 |
| **Monthly Total** | **$2,625** | **$1,250** |

**Verdict**: Use Claude for complex analysis (toxic combos, contextual risk), GPT-4 for high-volume simple enrichment. Hybrid approach ~$1,800/mo.

---

## 7. Secret Management: AWS Secrets Manager vs HashiCorp Vault

### Decision: AWS Secrets Manager (Cloud), Vault (Hybrid)

| Criteria | AWS Secrets Manager | HashiCorp Vault |
| --- | --- | --- |
| Multi-Cloud | AWS only | Yes |
| Dynamic Secrets | Limited (RDS) | Extensive |
| PKI | No | Yes |
| Ops Overhead | None | High |
| Auditing | CloudTrail | Built-in |
| Cost | Per secret + API calls | Self-hosted |

### Why AWS Secrets Manager (Cloud-Only)

1. **Zero Ops**: Fully managed
2. **IAM Integration**: Native AWS IAM policies
3. **Rotation**: Built-in for RDS, Redshift
4. **Lambda Integration**: Seamless for serverless

### Why Vault (Hybrid/Multi-Cloud)

1. **Multi-Cloud**: Single pane for AWS/Azure/GCP
2. **Dynamic DB Creds**: Ephemeral credentials
3. **PKI**: Certificate management
4. **SSH**: Dynamic SSH credentials

### Cost Analysis (100 secrets, 100K API calls/month)

| Component | AWS Secrets Manager | HashiCorp Vault (Self-Hosted) |
| --- | --- | --- |
| Secrets (100) | $40/mo | N/A |
| API Calls (100K) | $5/mo | N/A |
| Compute | N/A | 2x t3.medium = $60/mo |
| Storage | N/A | 50GB EBS = $5/mo |
| **Monthly Total** | **$45** | **$65** |

**Verdict**: AWS Secrets Manager for AWS-only. Vault if multi-cloud or need dynamic secrets/PKI.

---

## 8. Summary: Monthly Cost Estimate

### Small Deployment (10 users, 10K findings/month)

| Component | Choice | Monthly Cost |
| --- | --- | --- |
| Compute (EKS) | 2x m6i.large + control plane | $211 |
| Database (RDS) | db.t3.medium | $50 |
| Cache (ElastiCache) | cache.t3.micro | $12 |
| Queue (SQS) | Standard | $5 |
| AI (Claude) | 10K findings | $260 |
| Secrets | Secrets Manager | $10 |
| Networking | NAT, LB | $50 |
| **Total** | | **~$600/mo** |

### Medium Deployment (100 users, 100K findings/month)

| Component | Choice | Monthly Cost |
| --- | --- | --- |
| Compute (EKS) | 4x m6i.large + control plane | $365 |
| Database (RDS) | db.r6g.large Multi-AZ | $440 |
| Cache (ElastiCache) | cache.r6g.large | $220 |
| Queue (SQS) | Standard | $15 |
| AI (Hybrid) | 100K findings | $1,800 |
| Secrets | Secrets Manager | $50 |
| Networking | NAT, LB, Transit Gateway | $200 |
| Monitoring | CloudWatch, X-Ray | $100 |
| **Total** | | **~$3,200/mo** |

### Large Deployment (1000 users, 1M findings/month)

| Component | Choice | Monthly Cost |
| --- | --- | --- |
| Compute (EKS) | 10x m6i.xlarge + control plane | $1,500 |
| Database (RDS) | db.r6g.2xlarge Multi-AZ | $1,760 |
| Cache (ElastiCache) | cache.r6g.xlarge cluster | $880 |
| Queue (Kafka MSK) | 3x kafka.m5.large | $660 |
| AI (Hybrid) | 1M findings | $15,000 |
| Secrets | Vault cluster | $300 |
| Networking | Full mesh, WAF | $800 |
| Monitoring | Datadog/New Relic | $500 |
| **Total** | | **~$21,400/mo** |

---

## 9. Cost Optimization Recommendations

1. **Reserved Instances**: 35-50% savings on compute/database
2. **Savings Plans**: Commit to 1-year for additional discounts
3. **Spot Instances**: Use for batch processing (Checkov scans)
4. **AI Caching**: Cache AI responses for similar findings (30% reduction)
5. **S3 Intelligent-Tiering**: For finding archives
6. **Right-Sizing**: Monthly review of instance utilization

