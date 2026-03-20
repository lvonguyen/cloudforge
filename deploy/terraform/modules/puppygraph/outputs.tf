output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.puppygraph.id
}

output "public_ip" {
  description = "Public IP of the PuppyGraph instance"
  value       = aws_instance.puppygraph.public_ip
}

output "ui_url" {
  description = "PuppyGraph Web UI URL"
  value       = "http://${aws_instance.puppygraph.public_ip}:8081"
}

output "gremlin_url" {
  description = "Gremlin WebSocket endpoint"
  value       = "ws://${aws_instance.puppygraph.public_ip}:8182/gremlin"
}

output "opencypher_url" {
  description = "openCypher HTTP endpoint"
  value       = "http://${aws_instance.puppygraph.public_ip}:8184/cypher"
}

output "security_group_id" {
  description = "Security group ID for the PuppyGraph instance"
  value       = aws_security_group.puppygraph.id
}
