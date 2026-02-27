locals {
  resource_name = "${var.project_name}-${var.environment}-${var.service_name}"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: Cloud Run ──────────────────────────────────────────────────────────
resource "google_cloud_run_v2_service" "this" {
  count    = var.cloud_provider == "gcp" ? 1 : 0
  name     = local.resource_name
  location = var.region

  template {
    service_account = var.service_account

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      network_interfaces {
        network    = var.vpc_id
        subnetwork = var.subnet_ids[0]
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.container_image
      ports { container_port = var.container_port }
      resources {
        limits = { cpu = var.cpu, memory = var.memory }
      }

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secrets
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
    }
  }

  labels = local.common_tags
}

# ─── AWS: ECS Fargate ────────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "this" {
  count                    = var.cloud_provider == "aws" ? 1 : 0
  family                   = local.resource_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu == "1" ? "256" : var.cpu
  memory                   = replace(var.memory, "Mi", "")
  execution_role_arn       = var.service_account
  task_role_arn            = var.service_account

  container_definitions = jsonencode([{
    name      = var.service_name
    image     = var.container_image
    essential = true
    portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]
    environment = [for k, v in var.env_vars : { name = k, value = v }]
    secrets     = [for k, v in var.secrets : { name = k, valueFrom = v }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/${local.resource_name}"
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])

  tags = local.common_tags
}

resource "aws_ecs_service" "this" {
  count           = var.cloud_provider == "aws" ? 1 : 0
  name            = local.resource_name
  cluster         = var.aws_ecs_cluster_id
  task_definition = aws_ecs_task_definition.this[0].arn
  desired_count   = var.min_instances
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = []  # Populated by networking module
    assign_public_ip = false  # Always private — policy enforced
  }

  tags = local.common_tags
}

# ─── Azure: Container Apps ───────────────────────────────────────────────────
resource "azurerm_container_app" "this" {
  count                        = var.cloud_provider == "azure" ? 1 : 0
  name                         = local.resource_name
  resource_group_name          = var.azure_resource_group
  container_app_environment_id = var.azure_container_env_id
  revision_mode                = "Single"

  template {
    min_replicas = var.min_instances
    max_replicas = var.max_instances

    container {
      name   = var.service_name
      image  = var.container_image
      cpu    = var.cpu
      memory = var.memory

      dynamic "env" {
        for_each = var.env_vars
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secrets
        content {
          name        = env.key
          secret_name = lower(replace(env.key, "_", "-"))
        }
      }
    }
  }

  tags = local.common_tags
}
