locals {
  resource_name = "${var.project_name}-${var.environment}-db"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })

  tier_map_gcp = {
    SMALL    = "db-f1-micro"
    STANDARD = "db-custom-2-7680"
  }

  tier_map_aws = {
    SMALL    = "db.t3.micro"
    STANDARD = "db.t3.medium"
  }

  tier_map_azure = {
    SMALL    = "B_Standard_B1ms"
    STANDARD = "GP_Standard_D2s_v3"
  }
}

# ─── GCP: Cloud SQL PostgreSQL ───────────────────────────────────────────────
resource "google_sql_database_instance" "this" {
  count            = var.cloud_provider == "gcp" ? 1 : 0
  name             = local.resource_name
  database_version = var.db_version
  region           = var.region

  settings {
    tier              = local.tier_map_gcp[var.instance_tier]
    availability_type = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_size         = var.storage_gb
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    backup_configuration {
      enabled                        = var.backup_enabled
      point_in_time_recovery_enabled = var.environment == "prod"
      start_time                     = "03:00"
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.vpc_id
      require_ssl     = true
    }

    maintenance_window {
      day          = 7  # Sunday
      hour         = 4
      update_track = "stable"
    }

    user_labels = local.common_tags
  }

  deletion_protection = var.environment == "prod"
}

resource "google_sql_database" "this" {
  count    = var.cloud_provider == "gcp" ? 1 : 0
  name     = var.db_name
  instance = google_sql_database_instance.this[0].name
}

resource "google_sql_user" "this" {
  count    = var.cloud_provider == "gcp" ? 1 : 0
  name     = "${var.project_name}-app"
  instance = google_sql_database_instance.this[0].name
  type     = "BUILT_IN"
}

# ─── AWS: RDS PostgreSQL ─────────────────────────────────────────────────────
resource "aws_db_instance" "this" {
  count                       = var.cloud_provider == "aws" ? 1 : 0
  identifier                  = local.resource_name
  engine                      = "postgres"
  engine_version              = "15"
  instance_class              = local.tier_map_aws[var.instance_tier]
  allocated_storage           = var.storage_gb
  storage_encrypted           = true
  db_name                     = var.db_name
  username                    = "${replace(var.project_name, "-", "_")}_app"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this[0].name
  vpc_security_group_ids      = []  # Populated by networking module
  publicly_accessible         = false
  multi_az                    = var.environment == "prod"
  backup_retention_period     = var.backup_enabled ? 7 : 0
  skip_final_snapshot         = var.environment != "prod"
  final_snapshot_identifier   = var.environment == "prod" ? "${local.resource_name}-final" : null
  tags                        = local.common_tags
}

resource "aws_db_subnet_group" "this" {
  count      = var.cloud_provider == "aws" ? 1 : 0
  name       = "${local.resource_name}-subnets"
  subnet_ids = var.subnet_ids
  tags       = local.common_tags
}

# ─── Azure: PostgreSQL Flexible Server ───────────────────────────────────────
resource "azurerm_postgresql_flexible_server" "this" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = local.resource_name
  resource_group_name = var.azure_resource_group
  location            = var.region
  version             = "15"
  sku_name            = local.tier_map_azure[var.instance_tier]
  storage_mb          = var.storage_gb * 1024
  delegated_subnet_id = var.subnet_ids[0]
  zone                = var.environment == "prod" ? "1" : null

  authentication {
    password_auth_enabled = true
  }

  backup_retention_days        = var.backup_enabled ? 7 : 1
  geo_redundant_backup_enabled = var.environment == "prod"

  tags = local.common_tags
}
