variable "ami_id" {
  description = "PuppyGraph Enterprise AMI from AWS Marketplace"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type (r6i.xlarge recommended for 32GB RAM)"
  type        = string
  default     = "r6i.xlarge"
}

variable "vpc_id" {
  description = "VPC ID for the PuppyGraph instance"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID (public subnet for POC; private for production)"
  type        = string
}

variable "allowed_cidr" {
  description = "CIDR block allowed to access PuppyGraph ports (e.g. your IP)"
  type        = string
}

variable "key_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "pg_host" {
  description = "PostgreSQL host for PuppyGraph to connect to"
  type        = string
}

variable "pg_port" {
  description = "PostgreSQL port"
  type        = number
  default     = 5432
}

variable "pg_database" {
  description = "PostgreSQL database name"
  type        = string
  default     = "aegis"
}

variable "pg_user" {
  description = "PostgreSQL username"
  type        = string
  default     = "aegis"
}

variable "pg_password" {
  description = "PostgreSQL password"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
