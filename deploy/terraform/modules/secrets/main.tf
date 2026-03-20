locals {
  resource_name = "${var.project_name}-${var.environment}-secrets"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Secret Manager ──────────────────────────────────────────────────────

resource "google_secret_manager_secret" "this" {
  for_each  = var.cloud_provider == "gcp" ? var.secret_names : toset([])
  secret_id = "${local.resource_name}-${each.key}"

  replication {
    auto {}
  }

  labels = local.common_tags
}

resource "google_secret_manager_secret_iam_member" "accessor" {
  for_each  = var.cloud_provider == "gcp" && var.service_account != "" ? var.secret_names : toset([])
  secret_id = google_secret_manager_secret.this[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account}"
}

# ─── AWS: Secrets Manager ─────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "this" {
  for_each                = var.cloud_provider == "aws" ? var.secret_names : toset([])
  name                    = "${local.resource_name}/${each.key}"
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
  kms_key_id              = var.kms_key_id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-${each.key}"
  })
}

resource "aws_secretsmanager_secret_rotation" "this" {
  for_each            = var.cloud_provider == "aws" && var.enable_rotation ? var.secret_names : toset([])
  secret_id           = aws_secretsmanager_secret.this[each.key].id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}

# ─── Azure: Key Vault + Secret Slots ─────────────────────────────────────────

resource "azurerm_key_vault" "this" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = replace(local.resource_name, "-", "")
  resource_group_name = var.azure_resource_group
  location            = var.region
  tenant_id           = var.azure_tenant_id
  sku_name            = "standard"

  purge_protection_enabled   = var.environment == "prod"
  soft_delete_retention_days = var.environment == "prod" ? 90 : 7

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
  }

  tags = local.common_tags
}

resource "azurerm_key_vault_secret" "this" {
  for_each     = var.cloud_provider == "azure" ? var.secret_names : toset([])
  name         = each.key
  value        = "PLACEHOLDER"
  key_vault_id = azurerm_key_vault.this[0].id

  lifecycle {
    ignore_changes = [value]
  }
}
