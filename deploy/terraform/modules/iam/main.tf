locals {
  resource_name = "${var.project_name}-${var.environment}-iam"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Service Account + IAM Bindings ──────────────────────────────────────

resource "google_service_account" "app" {
  count        = var.cloud_provider == "gcp" ? 1 : 0
  account_id   = "${var.project_name}-${var.environment}-app"
  display_name = "CloudForge ${var.environment} application service account"
}

resource "google_project_iam_member" "app_roles" {
  for_each = var.cloud_provider == "gcp" ? toset(var.gcp_roles) : toset([])
  project  = var.gcp_project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.app[0].email}"
}

resource "google_service_account" "cost_reader" {
  count        = var.cloud_provider == "gcp" && var.enable_finops ? 1 : 0
  account_id   = "${var.project_name}-${var.environment}-finops"
  display_name = "CloudForge ${var.environment} FinOps cost reader"
}

resource "google_project_iam_member" "cost_reader" {
  count   = var.cloud_provider == "gcp" && var.enable_finops ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/billing.viewer"
  member  = "serviceAccount:${google_service_account.cost_reader[0].email}"
}

# ─── AWS: IAM Roles + Policies ────────────────────────────────────────────────

resource "aws_iam_role" "app" {
  count = var.cloud_provider == "aws" ? 1 : 0
  name  = "${local.resource_name}-app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "secrets_access" {
  count = var.cloud_provider == "aws" ? 1 : 0
  name  = "${local.resource_name}-secrets-access"
  role  = aws_iam_role.app[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
      ]
      Resource = "arn:aws:secretsmanager:${var.region}:*:secret:${var.project_name}-${var.environment}-*"
    }]
  })
}

resource "aws_iam_role" "cost_reader" {
  count = var.cloud_provider == "aws" && var.enable_finops ? 1 : 0
  name  = "${local.resource_name}-finops"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cost_reader" {
  count = var.cloud_provider == "aws" && var.enable_finops ? 1 : 0
  name  = "${local.resource_name}-finops-cost-reader"
  role  = aws_iam_role.cost_reader[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetCostForecast",
          "ce:GetReservationUtilization",
          "ce:GetSavingsPlansUtilization",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "budgets:ViewBudget",
          "budgets:DescribeBudgetActionsForBudget",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "waf_access" {
  count = var.cloud_provider == "aws" && var.enable_waf ? 1 : 0
  name  = "${local.resource_name}-waf-access"
  role  = aws_iam_role.app[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "wafv2:GetWebACL",
        "wafv2:ListWebACLs",
        "wafv2:GetRuleGroup",
        "wafv2:ListRuleGroups",
        "wafv2:UpdateWebACL",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "container_scanning" {
  count = var.cloud_provider == "aws" && var.enable_container_scanning ? 1 : 0
  name  = "${local.resource_name}-container-scanning"
  role  = aws_iam_role.app[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:ListImages",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:GetFindingsReportStatus",
        ]
        Resource = "*"
      },
    ]
  })
}

# ─── Azure: Managed Identity + Role Assignments ──────────────────────────────

resource "azurerm_user_assigned_identity" "app" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = "${local.resource_name}-app"
  resource_group_name = var.azure_resource_group
  location            = var.region

  tags = local.common_tags
}

resource "azurerm_role_assignment" "keyvault_reader" {
  count                = var.cloud_provider == "azure" ? 1 : 0
  scope                = var.azure_subscription_scope
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app[0].principal_id
}

resource "azurerm_user_assigned_identity" "cost_reader" {
  count               = var.cloud_provider == "azure" && var.enable_finops ? 1 : 0
  name                = "${local.resource_name}-finops"
  resource_group_name = var.azure_resource_group
  location            = var.region

  tags = local.common_tags
}

resource "azurerm_role_assignment" "cost_reader" {
  count                = var.cloud_provider == "azure" && var.enable_finops ? 1 : 0
  scope                = var.azure_subscription_scope
  role_definition_name = "Cost Management Reader"
  principal_id         = azurerm_user_assigned_identity.cost_reader[0].principal_id
}

resource "azurerm_role_assignment" "container_reader" {
  count                = var.cloud_provider == "azure" && var.enable_container_scanning ? 1 : 0
  scope                = var.azure_subscription_scope
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app[0].principal_id
}
