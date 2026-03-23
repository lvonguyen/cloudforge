# ─── CSPM Reader Policies ─────────────────────────────────────────────────────
#
# Cross-tenant read-only access for finding ingestion.
#
# Architecture:
#   Central security account → OIDC federation → haea-cg-app role
#   haea-cg-app role → AssumeRole → haea-cs-read-automation in each tenant
#
# Each tenant account needs:
#   1. IAM role: haea-cs-read-automation (trusts central security account)
#   2. Attached policy: haea-cs-read-automation-policy (SecurityHub + Config + GuardDuty + IAM read)
#
# The central account needs:
#   1. OIDC identity provider (GitLab or GitHub)
#   2. IAM role: haea-cg-app (trusts OIDC provider)
#   3. Policy: sts:AssumeRole into all tenant reader roles

# ─── Central Account: OIDC Provider ──────────────────────────────────────────

resource "aws_iam_openid_connect_provider" "gitlab" {
  url             = var.oidc_issuer_url
  client_id_list  = [var.oidc_audience]
  thumbprint_list = ["cf23df2207d99a74fbe169e956accb1535255e33"] # placeholder — update with actual

  tags = {
    Name    = "${var.project_name}-gitlab-oidc"
    purpose = "CI/CD federation for Cloud Guard CSPM"
  }
}

# ─── Central Account: App Role (OIDC-federated) ──────────────────────────────

resource "aws_iam_role" "app" {
  name = "${var.project_name}-${var.environment}-app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.gitlab.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(var.oidc_issuer_url, "https://", "")}:aud" = var.oidc_audience
          }
          StringLike = {
            "${replace(var.oidc_issuer_url, "https://", "")}:sub" = var.oidc_subject_claim
          }
        }
      },
      {
        # Also allow ECS tasks to assume this role (for runtime)
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# ─── Central Account: Cross-Account AssumeRole Policy ────────────────────────

resource "aws_iam_role_policy" "assume_tenant_readers" {
  name = "${var.project_name}-assume-tenant-readers"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Resource = [
        for tenant in var.aws_tenant_accounts :
        "arn:aws:iam::${tenant.account_id}:role/${tenant.role_name}"
      ]
    }]
  })
}

# ─── Tenant Accounts: CSPM Reader Role (one per tenant) ─────────────────────
#
# NOTE: These resources must be applied with provider aliases configured
# for each tenant account. In practice, you'll either:
#   a) Use `provider = aws.tenant_xxx` aliases with assume_role, or
#   b) Apply these as a separate TF workspace per tenant, or
#   c) Use AWS CloudFormation StackSets from the management account
#
# Below is the TEMPLATE for what goes into each tenant account.
# Uncomment and configure provider aliases for your deployment model.

# resource "aws_iam_role" "cspm_reader" {
#   for_each = var.aws_tenant_accounts
#   provider = aws.tenant[each.key]  # requires provider alias
#
#   name = each.value.role_name
#
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect = "Allow"
#       Principal = {
#         AWS = aws_iam_role.app.arn  # central security account app role
#       }
#       Action = "sts:AssumeRole"
#       Condition = {
#         StringEquals = {
#           "sts:ExternalId" = "${var.project_name}-cspm"
#         }
#       }
#     }]
#   })
# }

# ─── CSPM Reader Policy Document (attach to reader role in each tenant) ──────

# This is the actual permissions policy. Export as JSON for manual application
# or attach via aws_iam_role_policy in each tenant provider.

locals {
  cspm_reader_policy = {
    Version = "2012-10-17"
    Statement = [
      # ── SecurityHub: Finding ingestion ──
      {
        Sid    = "SecurityHubRead"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:ListFindings",
          "securityhub:GetInsights",
          "securityhub:ListInsights",
          "securityhub:DescribeHub",
          "securityhub:DescribeStandards",
          "securityhub:DescribeStandardsControls",
          "securityhub:GetEnabledStandards",
          "securityhub:ListSecurityControlDefinitions",
          "securityhub:BatchGetSecurityControls",
        ]
        Resource = "*"
      },
      # ── AWS Config: Configuration compliance ──
      {
        Sid    = "ConfigRead"
        Effect = "Allow"
        Action = [
          "config:DescribeComplianceByConfigRule",
          "config:DescribeComplianceByResource",
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceSummaryByConfigRule",
          "config:GetComplianceSummaryByResourceType",
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders",
          "config:GetResourceConfigHistory",
          "config:ListDiscoveredResources",
          "config:SelectResourceConfig",
        ]
        Resource = "*"
      },
      # ── GuardDuty: Threat detection findings ──
      {
        Sid    = "GuardDutyRead"
        Effect = "Allow"
        Action = [
          "guardduty:GetDetector",
          "guardduty:ListDetectors",
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetFindingsStatistics",
          "guardduty:ListMembers",
        ]
        Resource = "*"
      },
      # ── IAM: Identity audit (users, roles, policies) ──
      {
        Sid    = "IAMAudit"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetAccessKeyLastUsed",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "iam:GetAccountAuthorizationDetails",
          "iam:GetAccountSummary",
        ]
        Resource = "*"
      },
      # ── Resource inventory (EC2, RDS, S3) ──
      {
        Sid    = "ResourceInventory"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeVolumes",
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "s3:ListAllMyBuckets",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "ssm:DescribeInstanceInformation",
        ]
        Resource = "*"
      },
      # ── SSM: Patch compliance ──
      {
        Sid    = "SSMCompliance"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstancePatchStates",
          "ssm:GetPatchBaseline",
          "ssm:DescribePatchBaselines",
        ]
        Resource = "*"
      },
      # ── CloudTrail: Activity analysis for attack path lateral movement ──
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:GetInsightSelectors",
          "cloudtrail:ListTrails",
        ]
        Resource = "*"
      },
      # ── Resource detail: Attack path graph edge construction ──
      # Network topology (entry points, lateral movement paths)
      {
        Sid    = "NetworkTopology"
        Effect = "Allow"
        Action = [
          "ec2:DescribeRouteTables",
          "ec2:DescribeNatGateways",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeTransitGateways",
          "ec2:DescribeTransitGatewayAttachments",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeVpcEndpoints",
        ]
        Resource = "*"
      },
      # Load balancers (public-facing entry points)
      {
        Sid    = "LoadBalancerRead"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeRules",
        ]
        Resource = "*"
      },
      # Serverless + container attack surface
      {
        Sid    = "ServerlessContainerRead"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:GetPolicy",
          "lambda:ListEventSourceMappings",
          "ecs:ListClusters",
          "ecs:DescribeClusters",
          "ecs:ListServices",
          "ecs:DescribeServices",
          "ecs:ListTasks",
          "ecs:DescribeTasks",
          "eks:ListClusters",
          "eks:DescribeCluster",
          "eks:ListNodegroups",
        ]
        Resource = "*"
      },
      # IAM Access Analyzer (external access paths)
      {
        Sid    = "AccessAnalyzerRead"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding",
        ]
        Resource = "*"
      },
      # KMS + Secrets Manager (encryption posture for blast radius scoring)
      {
        Sid    = "EncryptionPosture"
        Effect = "Allow"
        Action = [
          "kms:ListKeys",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "secretsmanager:ListSecrets",
          "secretsmanager:DescribeSecret",
        ]
        Resource = "*"
      },
    ]
  }

  # Cost reader policy (separate role, optional)
  cost_reader_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CostExplorerRead"
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetCostForecast",
          "ce:GetReservationUtilization",
          "ce:GetSavingsPlansUtilization",
          "ce:GetAnomalies",
          "ce:GetAnomalyMonitors",
        ]
        Resource = "*"
      },
      {
        Sid    = "BudgetsRead"
        Effect = "Allow"
        Action = [
          "budgets:ViewBudget",
          "budgets:DescribeBudgetActionsForBudget",
        ]
        Resource = "*"
      },
    ]
  }
}

# ─── Output policy JSON for manual / StackSet application ─────────────────────

output "cspm_reader_policy_json" {
  description = "CSPM reader policy JSON — apply to haea-cs-read-automation role in each tenant account"
  value       = jsonencode(local.cspm_reader_policy)
}

output "cspm_reader_trust_policy_json" {
  description = "Trust policy for tenant reader roles — trusts central security account app role"
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.app.arn
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "${var.project_name}-cspm"
        }
      }
    }]
  })
}

output "cost_reader_policy_json" {
  description = "Cost reader policy JSON — apply to haea-cg-cost-reader role in tenant accounts"
  value       = jsonencode(local.cost_reader_policy)
}

output "central_app_role_arn" {
  description = "ARN of the central OIDC-federated app role"
  value       = aws_iam_role.app.arn
}
