# 48-Hour Teardown Runbook

**Target:** Personal demo infrastructure in `lvn-personal` (431330216246), us-east-1
**Cost:** ~$88/mo (VPC+NAT+RDS+Redis+ECS+ALB) + ~$181/mo if PuppyGraph EC2 is running
**Calendar reminder:** April 20, 2026
**TF state:** LOCAL at `deploy/terraform/environments/personal/`

---

## 1. Pre-Teardown Checklist

```bash
# Authenticate
aws sso login --profile lvn-personal
export AWS_PROFILE=lvn-personal

# Snapshot RDS (automated backups are OFF — this is the only copy)
aws rds create-db-snapshot \
  --db-instance-identifier aegis-personal \
  --db-snapshot-identifier aegis-personal-final-$(date +%Y%m%d)

# Wait for snapshot to complete
aws rds wait db-snapshot-available \
  --db-snapshot-identifier aegis-personal-final-$(date +%Y%m%d)

# Export findings JSON from R2 (if not already local)
# curl -o findings-backup.json https://r2-url/findings.json

# Screenshot the live demo (browser or CLI)
# open https://cloudguard.lvonguyen.com
# open https://api.cloudforge-demo.lvonguyen.com/health

# Verify TF state exists
ls -la deploy/terraform/environments/personal/terraform.tfstate
```

**Confirm before proceeding:**
- [ ] RDS snapshot completed
- [ ] Screenshots/GIFs captured for portfolio
- [ ] Local copy of `terraform.tfstate` backed up (cp to ~/backups/)
- [ ] `findings.json` archived locally or in R2

---

## 2. PuppyGraph Shutdown

PuppyGraph EC2: `i-096bba925c464985f` (100.52.183.146:8081), container: `puppy`

```bash
# If PuppyGraph is currently deployed (check var.deploy_puppygraph):

# Option A: Stop container only (keeps EC2 for quick restart)
aws ssm start-session --target i-096bba925c464985f
# Inside SSM session:
sudo docker stop puppy
exit

# Option B: Terminate EC2 via TF (preferred — saves ~$181/mo)
cd deploy/terraform/environments/personal
terraform plan -var="deploy_puppygraph=false" -out=teardown-puppy.tfplan
terraform apply teardown-puppy.tfplan
```

If PuppyGraph was already disabled (`deploy_puppygraph=false`), skip this step.

---

## 3. Terraform Destroy

```bash
cd deploy/terraform/environments/personal

# Backup state before destroy
cp terraform.tfstate terraform.tfstate.pre-destroy-$(date +%Y%m%d)

# Plan destroy — review carefully
terraform plan -destroy -out=teardown.tfplan

# Verify the plan shows ~39 resources to destroy:
#   - module.network (VPC, subnets, NAT, IGW, route tables)
#   - module.database (RDS instance, subnet group, parameter group)
#   - module.redis (ElastiCache cluster, subnet group)
#   - module.secrets (6 Secrets Manager secrets)
#   - module.aegis_api (ECS service, task def)
#   - aws_ecs_cluster, aws_ecr_repository
#   - aws_lb, aws_lb_target_group, aws_lb_listener
#   - aws_security_group (alb, ecs), SG rules
#   - aws_iam_role + policies
#   - aws_cloudwatch_log_group

# Execute
terraform apply teardown.tfplan
```

**[!] If destroy fails on a resource:**
```bash
# Common: ECR repo with images (force_delete=true should handle it)
# Common: SG dependency cycles — destroy ALB first, then SGs
# Fallback: terraform state rm <resource> then manual console delete
```

---

## 4. CF Pages / Fly.io Cleanup (Optional — Free Tier)

These cost $0 but leave stale endpoints. Clean up if you want a pristine state.

```bash
# CF Pages — delete projects (removes builds + custom domains)
# cloudguard -> cloudguard.lvonguyen.com
# cloudforge-demo -> cloudaegis-demo.lvonguyen.com
# Use CF dashboard or API:
# curl -X DELETE "https://api.cloudflare.com/client/v4/accounts/{account_id}/pages/projects/cloudguard" \
#   -H "Authorization: Bearer {token}"

# Fly.io — delete app
fly apps destroy cloudforge-api --yes
# Removes: api.cloudforge-demo.lvonguyen.com backend
```

**Recommendation:** Keep CF Pages (free, useful for portfolio). Only tear down if decommissioning entirely.

---

## 5. DNS Cleanup

Cloudflare proxied records to remove after AWS teardown:

```bash
# These will 522/502 after ALB is destroyed — clean up in CF dashboard:
# - api.cloudforge-demo.lvonguyen.com (CNAME -> ALB DNS name)

# If keeping CF Pages, these stay:
# - cloudguard.lvonguyen.com (CF Pages auto-managed)
# - cloudaegis-demo.lvonguyen.com (CF Pages auto-managed)

# If Fly.io is destroyed:
# - api.cloudforge-demo.lvonguyen.com (CNAME -> cloudforge-api.fly.dev)
```

Delete stale DNS records in the CF dashboard under the `lvonguyen.com` zone.

---

## 6. AWS Service Cleanup (Non-TF Managed)

These were enabled manually or by other tooling — TF destroy will NOT remove them:

```bash
# SecurityHub
aws securityhub disable-security-hub

# GuardDuty
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty delete-detector --detector-id "$DETECTOR"

# AWS Config
aws configservice stop-configuration-recorder --configuration-recorder-name default
aws configservice delete-configuration-recorder --configuration-recorder-name default
aws configservice delete-delivery-channel --delivery-channel-name default
```

---

## 7. Verification

```bash
# Confirm no running resources
aws ecs list-clusters --query 'clusterArns'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'
aws elasticache describe-cache-clusters --query 'CacheClusters[*].CacheClusterId'
aws ec2 describe-instances --filters "Name=tag:project,Values=aegis" \
  --query 'Reservations[*].Instances[*].[InstanceId,State.Name]'
aws elbv2 describe-load-balancers --query 'LoadBalancers[*].LoadBalancerArn'
aws ec2 describe-nat-gateways --filter "Name=state,Values=available" \
  --query 'NatGateways[*].NatGatewayId'

# Confirm endpoints are down
curl -s -o /dev/null -w "%{http_code}" https://api.cloudforge-demo.lvonguyen.com/health
# Expected: 000 (connection refused) or 522 (CF can't reach origin)

# Check Cost Explorer (next day — billing lags ~24h)
aws ce get-cost-and-usage \
  --time-period Start=$(date -v-1d +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics UnblendedCost \
  --filter '{"Dimensions":{"Key":"LINKED_ACCOUNT","Values":["431330216246"]}}'

# Verify RDS snapshot exists (for re-spin)
aws rds describe-db-snapshots \
  --db-snapshot-identifier aegis-personal-final-$(date +%Y%m%d)
```

**Expected outcome:** All commands return empty arrays. Cost should drop to ~$0 within 48h (NAT gateway billing stops immediately, RDS/Redis within the hour).

---

## 8. Config Revert for Re-Spin (SMALL Tier)

To bring the demo back up at minimal cost, edit `main.tf` before `terraform apply`:

```hcl
# database module — downgrade from STANDARD
instance_tier  = "SMALL"    # was: "STANDARD" (db.t3.medium -> db.t3.micro)
storage_gb     = 20         # keep same

# redis module — already minimal, no change needed
memory_size_gb = 1
ha_enabled     = false

# compute module — reduce Fargate
cpu    = "256"              # was: "512"
memory = "512"              # was: "1024"

# Keep PuppyGraph OFF
# variable "deploy_puppygraph" default = false
```

**Estimated re-spin cost (SMALL):** ~$45/mo

---

## 9. Re-Spin Instructions

```bash
cd deploy/terraform/environments/personal

# Restore state (if you kept the pre-destroy backup)
# cp terraform.tfstate.pre-destroy-YYYYMMDD terraform.tfstate
# [!] Only do this if resources still exist. For a clean re-spin, start fresh.

# Apply with SMALL tier edits from section 8
terraform init
terraform plan -out=respin.tfplan
terraform apply respin.tfplan

# Restore RDS from snapshot (instead of empty DB)
# 1. Let TF create the new RDS instance
# 2. Then restore data:
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier aegis-personal-restored \
  --db-snapshot-identifier aegis-personal-final-YYYYMMDD \
  --db-instance-class db.t3.micro

# Rebuild + push container image
cd /path/to/cloudforge
docker build -t aegis-api .
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin 431330216246.dkr.ecr.us-east-1.amazonaws.com
docker tag aegis-api:latest 431330216246.dkr.ecr.us-east-1.amazonaws.com/aegis-personal-api:latest
docker push 431330216246.dkr.ecr.us-east-1.amazonaws.com/aegis-personal-api:latest

# Update container_image in main.tf back to :latest
# Then: terraform apply

# Re-populate secrets
aws secretsmanager put-secret-value --secret-id aegis-personal-secrets/jwt-secret \
  --secret-string "$(op read 'op://Development/aegis-personal-jwt-secret/credential')"

# Restore DNS in CF dashboard
# api.cloudforge-demo.lvonguyen.com -> new ALB DNS name (from TF output)

# Verify
curl https://api.cloudforge-demo.lvonguyen.com/health
```

---

## Quick Reference

| Resource | Identifier | Cost/mo |
|----------|-----------|---------|
| RDS | aegis-personal (db.t3.medium) | ~$25 |
| ElastiCache | aegis-personal (cache.t3.micro) | ~$12 |
| NAT Gateway | aegis-personal VPC | ~$32 |
| ECS Fargate | 0.5 vCPU / 1GB | ~$15 |
| ALB | aegis-personal-alb | ~$16 |
| PuppyGraph EC2 | i-096bba925c464985f (r6i.2xlarge) | ~$181 |
| CF Pages | cloudguard, cloudforge-demo | $0 |
| Fly.io | cloudforge-api | $0 |
