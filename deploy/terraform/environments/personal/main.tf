# Cloud Aegis — Personal Demo Environment
# Deploys the full pipeline to lvn-personal (431330216246) for portfolio demo.
# Teardown target: 2026-04-20 (calendar reminder set).

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local backend — single operator, temporary demo
}

provider "aws" {
  region  = var.region
  profile = "lvn-personal"

  default_tags {
    tags = {
      project     = var.project_name
      environment = "personal"
      managed_by  = "terraform"
    }
  }
}

# Stub providers — required by multi-cloud modules (count=0, no API calls made)
provider "azurerm" {
  features {}
  skip_provider_registration = true
}

provider "google" {
  project = "unused"
}

# ─── Data Sources ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

data "aws_security_group" "default" {
  vpc_id = module.network.vpc_id
  name   = "default"
}

# ─── Locals ────────────────────────────────────────────────────────────────────

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = "${var.project_name}-personal"

  common_tags = {
    application_id = var.project_name
    environment    = "personal"
    cost_center    = "personal"
    owner          = "liem"
  }
}

# ─── Network ───────────────────────────────────────────────────────────────────

module "network" {
  source           = "../../modules/network"
  cloud_provider   = var.cloud_provider
  project_name     = var.project_name
  environment      = "personal"
  region           = var.region
  cidr_block       = "10.0.0.0/16"
  subnet_count     = 2
  enable_nat       = true
  enable_flow_logs = false # Save cost for personal demo
}

# ─── ECR ───────────────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "aegis" {
  name                 = "${local.name}-api"
  image_tag_mutability = "MUTABLE"
  force_delete         = true # Personal env — allow easy teardown

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}

# ─── ECS Cluster ───────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "disabled" # Save cost for personal demo
  }

  tags = local.common_tags
}

# ─── IAM: ECS Execution + Task Role ───────────────────────────────────────────
# Compute module uses a single service_account for both execution_role_arn and
# task_role_arn. Combined role with ECR/logs/secrets (execution) + SecurityHub
# (application) permissions. Separate roles for HAEA production.

resource "aws_iam_role" "ecs" {
  name = "${local.name}-ecs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_policy" "ecs_app" {
  name = "${local.name}-ecs-app"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          "arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:${local.name}-secrets/*",
          # RDS managed master password (auto-created by manage_master_user_password)
          "arn:aws:secretsmanager:${var.region}:${local.account_id}:secret:rds!*",
        ]
      },
      {
        Sid    = "SecurityHubRead"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:ListFindings",
          "securityhub:BatchGetSecurityControls",
          "securityhub:GetSecurityControlDefinition",
          "securityhub:DescribeStandards",
          "securityhub:DescribeStandardsControls",
        ]
        Resource = "*"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_app" {
  role       = aws_iam_role.ecs.name
  policy_arn = aws_iam_policy.ecs_app.arn
}

# ─── Security Groups ──────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "ALB - inbound HTTP from internet"
  vpc_id      = module.network.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet (Cloudflare terminates TLS)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "ecs" {
  name        = "${local.name}-ecs"
  description = "ECS tasks - inbound from ALB on 8080"
  vpc_id      = module.network.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "API traffic from ALB"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

# Allow ECS → RDS/Redis via default VPC SG (workaround: database/redis modules
# don't accept security_group_ids as input)
resource "aws_security_group_rule" "default_rds_from_ecs" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = data.aws_security_group.default.id
  description              = "PostgreSQL from ECS tasks"
}

resource "aws_security_group_rule" "default_redis_from_ecs" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = data.aws_security_group.default.id
  description              = "Redis from ECS tasks"
}

# ─── ALB ───────────────────────────────────────────────────────────────────────

resource "aws_lb" "this" {
  name               = "${local.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.network.public_subnet_ids

  tags = local.common_tags
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name}-api"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = module.network.vpc_id
  target_type = "ip" # Fargate uses awsvpc networking

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }

  tags = local.common_tags
}

# ─── CloudWatch Log Group ──────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.name}-api"
  retention_in_days = 7 # Short retention for personal demo

  tags = local.common_tags
}

# ─── Database ──────────────────────────────────────────────────────────────────

module "database" {
  source         = "../../modules/database"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "personal"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  instance_tier  = "SMALL"
  storage_gb     = 20
  backup_enabled = false
  region         = var.region
}

# ─── Redis ─────────────────────────────────────────────────────────────────────

module "redis" {
  source         = "../../modules/redis"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "personal"
  vpc_id         = module.network.vpc_id
  subnet_ids     = module.network.subnet_ids
  memory_size_gb = 1
  ha_enabled     = false
  region         = var.region
}

# ─── Secrets ───────────────────────────────────────────────────────────────────

module "secrets" {
  source         = "../../modules/secrets"
  cloud_provider = var.cloud_provider
  project_name   = var.project_name
  environment    = "personal"
  region         = var.region

  secret_names = toset([
    "db-url",
    "jwt-secret",
    "redis-password",
  ])

  tags = local.common_tags
}

# ─── Compute: Aegis API ───────────────────────────────────────────────────────

module "aegis_api" {
  source          = "../../modules/compute"
  cloud_provider  = var.cloud_provider
  project_name    = var.project_name
  environment     = "personal"
  service_name    = "api"
  container_image = "${aws_ecr_repository.aegis.repository_url}:latest"
  container_port  = 8080
  vpc_id          = module.network.vpc_id
  subnet_ids      = module.network.subnet_ids
  min_instances   = 1
  max_instances   = 1
  cpu             = "256"
  memory          = "512"
  region          = var.region

  aws_ecs_cluster_id = aws_ecs_cluster.this.id
  service_account    = aws_iam_role.ecs.arn
  security_group_ids = [aws_security_group.ecs.id]
  target_group_arn   = aws_lb_target_group.api.arn

  env_vars = {
    GRC_PROVIDER         = "postgres"
    APP_ENV              = "production"
    RATE_LIMIT_ENABLED   = "true"
    AEGIS_AI_ENABLED     = "false"
    CORS_ALLOWED_ORIGINS = "https://cloudguard.lvonguyen.com"
    REDIS_ADDR           = "${module.redis.host}:${module.redis.port}"
  }

  secrets = {
    AEGIS_DATABASE_URL   = module.secrets.secret_ids["db-url"]
    AEGIS_JWT_SECRET     = module.secrets.secret_ids["jwt-secret"]
    AEGIS_REDIS_PASSWORD = module.secrets.secret_ids["redis-password"]
  }

  tags = local.common_tags
}
