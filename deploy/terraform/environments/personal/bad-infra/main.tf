# Bad Infrastructure — Intentionally misconfigured resources for SecurityHub demo.
# These generate real SecurityHub findings in lvn-personal (431330216246).
# Tagged purpose=security-demo for easy identification and cleanup.
#
# TEARDOWN: terraform destroy (or by 2026-04-20 with parent infra)

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "lvn-personal"

  default_tags {
    tags = {
      purpose    = "security-demo"
      managed_by = "terraform"
      project    = "aegis"
    }
  }
}

locals {
  prefix = "aegis-bad"
}

# ---------------------------------------------------------------------------
# 1. S3 bucket — public read ACL (S3.2)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "public" {
  bucket        = "${local.prefix}-public-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.public]
}

# ---------------------------------------------------------------------------
# 2. S3 bucket — no encryption (S3.4)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "unencrypted" {
  bucket        = "${local.prefix}-unencrypted-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Intentionally no server_side_encryption_configuration

# ---------------------------------------------------------------------------
# 3. S3 bucket — no versioning (S3.8)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "unversioned" {
  bucket        = "${local.prefix}-unversioned-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "unversioned" {
  bucket = aws_s3_bucket.unversioned.id
  versioning_configuration {
    status = "Suspended"
  }
}

# ---------------------------------------------------------------------------
# 4. Security group — SSH from 0.0.0.0/0 (EC2.19)
# ---------------------------------------------------------------------------
resource "aws_security_group" "open_ssh" {
  name        = "${local.prefix}-open-ssh"
  description = "Intentionally open SSH for SecurityHub demo"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH open to world - demo finding"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# 5. Security group — RDP from 0.0.0.0/0 (EC2.20)
# ---------------------------------------------------------------------------
resource "aws_security_group" "open_rdp" {
  name        = "${local.prefix}-open-rdp"
  description = "Intentionally open RDP for SecurityHub demo"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP open to world - demo finding"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# 6. IAM user — console access, no MFA (IAM.5)
# ---------------------------------------------------------------------------
resource "aws_iam_user" "no_mfa" {
  name          = "${local.prefix}-no-mfa-user"
  force_destroy = true
}

resource "aws_iam_user_login_profile" "no_mfa" {
  user                    = aws_iam_user.no_mfa.name
  password_reset_required = true
}

# ---------------------------------------------------------------------------
# 7. IAM policy — wildcard admin (IAM.1)
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "wildcard_admin" {
  name        = "${local.prefix}-wildcard-admin"
  description = "Full admin wildcard policy — demo finding"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "wildcard" {
  user       = aws_iam_user.no_mfa.name
  policy_arn = aws_iam_policy.wildcard_admin.arn
}

# ---------------------------------------------------------------------------
# 8. EBS volume — unencrypted (EC2.3)
# ---------------------------------------------------------------------------
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = false
  type              = "gp3"

  tags = {
    Name = "${local.prefix}-unencrypted-ebs"
  }
}

# ---------------------------------------------------------------------------
# 9. CloudTrail — no log file validation (CloudTrail.4)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail_logs" {
  bucket        = "${local.prefix}-trail-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "bad" {
  name                       = "${local.prefix}-trail"
  s3_bucket_name             = aws_s3_bucket.trail_logs.id
  enable_log_file_validation = false
  is_multi_region_trail      = false

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

# ---------------------------------------------------------------------------
# 10. SNS topic — no encryption (SNS.1)
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "unencrypted" {
  name = "${local.prefix}-unencrypted-topic"
  # Intentionally no kms_master_key_id
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "resource_arns" {
  description = "ARNs of bad-infra resources for SecurityHub filtering"
  value = {
    s3_public       = aws_s3_bucket.public.arn
    s3_unencrypted  = aws_s3_bucket.unencrypted.arn
    s3_unversioned  = aws_s3_bucket.unversioned.arn
    sg_ssh          = aws_security_group.open_ssh.arn
    sg_rdp          = aws_security_group.open_rdp.arn
    iam_user        = aws_iam_user.no_mfa.arn
    iam_policy      = aws_iam_policy.wildcard_admin.arn
    ebs_volume      = aws_ebs_volume.unencrypted.arn
    cloudtrail      = aws_cloudtrail.bad.arn
    sns_topic       = aws_sns_topic.unencrypted.arn
  }
}
