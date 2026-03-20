# PuppyGraph Enterprise on EC2 — POC deployment.
# Launches PuppyGraph from AWS Marketplace AMI, connects to existing Postgres.
# Terminate when trial ends (30 days from 2026-03-19).

locals {
  common_tags = merge(var.tags, {
    Project     = "aegis"
    Component   = "puppygraph"
    Environment = "poc"
    ManagedBy   = "terraform"
  })
}

# --- Security Group ---

resource "aws_security_group" "puppygraph" {
  name_prefix = "puppygraph-poc-"
  description = "PuppyGraph POC — UI, Gremlin, openCypher from allowed CIDR"
  vpc_id      = var.vpc_id

  ingress {
    description = "PuppyGraph Web UI"
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "Gremlin WebSocket"
    from_port   = 8182
    to_port     = 8182
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "openCypher HTTP"
    from_port   = 8184
    to_port     = 8184
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  ingress {
    description = "SSH (maintenance)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "puppygraph-poc-sg" })
}

# --- IAM Role (SSM for maintenance) ---

resource "aws_iam_role" "puppygraph" {
  name_prefix = "puppygraph-poc-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.puppygraph.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "puppygraph" {
  name_prefix = "puppygraph-poc-"
  role        = aws_iam_role.puppygraph.name
}

# --- EC2 Instance ---

resource "aws_instance" "puppygraph" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.puppygraph.id]
  iam_instance_profile   = aws_iam_instance_profile.puppygraph.name
  key_name               = var.key_name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail

    # Install Docker if not present (Marketplace AMI may already have it)
    if ! command -v docker &>/dev/null; then
      yum update -y
      yum install -y docker
      systemctl enable docker
      systemctl start docker
    fi

    # Pull PuppyGraph and run
    docker pull puppygraph/puppygraph-enterprise:latest

    # Write schema config
    mkdir -p /opt/puppygraph
    cat > /opt/puppygraph/schema.json << 'SCHEMA'
    ${file("${path.module}/../../docker/puppygraph/schema.json")}
    SCHEMA

    # Start PuppyGraph container
    docker run -d \
      --name puppygraph \
      --restart unless-stopped \
      -p 8081:8081 \
      -p 8182:8182 \
      -p 8184:8184 \
      -e PG_HOST=${var.pg_host} \
      -e PG_PORT=${var.pg_port} \
      -e PG_DATABASE=${var.pg_database} \
      -e PG_USER=${var.pg_user} \
      -e PG_PASSWORD=${var.pg_password} \
      -v /opt/puppygraph/schema.json:/opt/puppygraph/config/schema.json:ro \
      puppygraph/puppygraph-enterprise:latest
  USERDATA

  tags = merge(local.common_tags, { Name = "puppygraph-poc" })
}
