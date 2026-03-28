output "alb_dns" {
  description = "ALB DNS name — CNAME api.cloudforge-demo.lvonguyen.com to this"
  value       = aws_lb.this.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.aegis.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.this.name
}

output "rds_endpoint" {
  description = "RDS endpoint (host:port)"
  value       = module.database.connection_name
}

output "rds_db_name" {
  description = "RDS database name"
  value       = module.database.database_name
}

output "redis_endpoint" {
  description = "Redis endpoint (host:port)"
  value       = "${module.redis.host}:${module.redis.port}"
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.network.vpc_id
}

output "secret_arns" {
  description = "Secrets Manager ARNs for post-apply population"
  value       = module.secrets.secret_ids
}

output "puppygraph_ui_url" {
  description = "PuppyGraph Web UI URL (operator access only)"
  value       = var.deploy_puppygraph ? module.puppygraph[0].ui_url : null
}

output "puppygraph_private_ip" {
  description = "PuppyGraph private IP (ECS within-VPC access)"
  value       = var.deploy_puppygraph ? module.puppygraph[0].private_ip : null
}
