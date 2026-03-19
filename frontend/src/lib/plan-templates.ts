import { branding } from '@/lib/branding'
import type { TerraformPlan, DeployPreviewConfig } from '@/types/deploy'

function planForS3(config: DeployPreviewConfig): TerraformPlan {
  const bucketName = `cf-demo-${config.appId}-${Date.now().toString(36)}`
  return {
    format_version: '1.2',
    terraform_version: '1.9.8',
    planned_values: {
      root_module: {
        resources: [
          {
            address: 'aws_s3_bucket.demo',
            mode: 'managed',
            type: 'aws_s3_bucket',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                bucket: bucketName,
                force_destroy: true,
                tags: { team: String(config.configuration.tagTeam ?? 'platform'), environment: String(config.configuration.tagEnvironment ?? 'dev'), 'cost-center': String(config.configuration.tagCostCenter ?? 'CC-0000'), managed_by: branding.storagePrefix },
              },
            },
          },
          {
            address: 'aws_s3_bucket_server_side_encryption_configuration.demo',
            mode: 'managed',
            type: 'aws_s3_bucket_server_side_encryption_configuration',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                bucket: bucketName,
                rule: [{ apply_server_side_encryption_by_default: { sse_algorithm: String(config.configuration.encryption ?? 'AES256') } }],
              },
            },
          },
          {
            address: 'aws_s3_bucket_versioning.demo',
            mode: 'managed',
            type: 'aws_s3_bucket_versioning',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                bucket: bucketName,
                versioning_configuration: [{ status: config.configuration.versioning ? 'Enabled' : 'Suspended' }],
              },
            },
          },
        ],
      },
    },
    resource_changes: [],
  }
}

function planForEC2(config: DeployPreviewConfig): TerraformPlan {
  return {
    format_version: '1.2',
    terraform_version: '1.9.8',
    planned_values: {
      root_module: {
        resources: [
          {
            address: 'aws_instance.demo',
            mode: 'managed',
            type: 'aws_instance',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                ami: String(config.configuration.amiId || 'ami-0c02fb55956c7d316'),
                instance_type: String(config.configuration.instanceType || 't3.medium'),
                subnet_id: String(config.configuration.subnetId || 'subnet-0abc1234'),
                vpc_security_group_ids: ['sg-platform-demo'],
                tags: { Name: `cf-demo-${config.appId}`, team: String(config.configuration.tagTeam ?? ''), environment: String(config.configuration.tagEnvironment ?? 'dev') },
                metadata_options: { http_tokens: 'required', http_endpoint: 'enabled' },
                root_block_device: { encrypted: true, volume_type: 'gp3', volume_size: 20 },
              },
            },
          },
          {
            address: 'aws_security_group.demo',
            mode: 'managed',
            type: 'aws_security_group',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                name: `cf-demo-${config.appId}-sg`,
                description: `${branding.productName} demo security group`,
                ingress: [],
                egress: [{ from_port: 0, to_port: 0, protocol: '-1', cidr_blocks: ['0.0.0.0/0'] }],
              },
            },
          },
        ],
      },
    },
    resource_changes: [],
  }
}

function planForRDS(config: DeployPreviewConfig): TerraformPlan {
  return {
    format_version: '1.2',
    terraform_version: '1.9.8',
    planned_values: {
      root_module: {
        resources: [
          {
            address: 'aws_db_instance.demo',
            mode: 'managed',
            type: 'aws_db_instance',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                identifier: `cf-demo-${config.appId}`,
                engine: String(config.configuration.engine || 'postgres'),
                engine_version: config.configuration.engine === 'mysql' ? '8.0' : '16.4',
                instance_class: String(config.configuration.instanceClass || 'db.t3.medium'),
                allocated_storage: Number(config.configuration.storageGb || 20),
                storage_encrypted: true,
                publicly_accessible: false,
                multi_az: false,
                skip_final_snapshot: true,
                tags: { team: String(config.configuration.tagTeam ?? ''), environment: String(config.configuration.tagEnvironment ?? 'dev') },
              },
            },
          },
          {
            address: 'aws_db_subnet_group.demo',
            mode: 'managed',
            type: 'aws_db_subnet_group',
            name: 'demo',
            provider: 'provider["registry.terraform.io/hashicorp/aws"]',
            change: {
              actions: ['create'],
              before: null,
              after: {
                name: `cf-demo-${config.appId}-subnet-group`,
                subnet_ids: ['subnet-private-a', 'subnet-private-b'],
              },
            },
          },
        ],
      },
    },
    resource_changes: [],
  }
}

function planForK8s(config: DeployPreviewConfig): TerraformPlan {
  const isAKS = config.provider === 'azure'
  const providerName = isAKS
    ? 'provider["registry.terraform.io/hashicorp/azurerm"]'
    : 'provider["registry.terraform.io/hashicorp/google"]'

  return {
    format_version: '1.2',
    terraform_version: '1.9.8',
    planned_values: {
      root_module: {
        resources: [
          {
            address: isAKS ? 'azurerm_kubernetes_cluster.demo' : 'google_container_cluster.demo',
            mode: 'managed',
            type: isAKS ? 'azurerm_kubernetes_cluster' : 'google_container_cluster',
            name: 'demo',
            provider: providerName,
            change: {
              actions: ['create'],
              before: null,
              after: isAKS
                ? {
                    name: `cf-demo-${config.appId}`,
                    location: config.region,
                    dns_prefix: `cf-demo-${config.appId}`,
                    default_node_pool: {
                      name: 'default',
                      node_count: Number(config.configuration.nodeCount || 3),
                      vm_size: String(config.configuration.machineType || 'Standard_D2s_v3'),
                      enable_auto_scaling: Boolean(config.configuration.autoscaling),
                    },
                    tags: { team: String(config.configuration.tagTeam ?? ''), environment: String(config.configuration.tagEnvironment ?? 'dev') },
                  }
                : {
                    name: `cf-demo-${config.appId}`,
                    location: config.region,
                    initial_node_count: Number(config.configuration.nodeCount || 3),
                    node_config: {
                      machine_type: String(config.configuration.machineType || 'e2-standard-4'),
                      disk_size_gb: 50,
                    },
                    cluster_autoscaling: { enabled: Boolean(config.configuration.autoscaling) },
                    labels: { team: String(config.configuration.tagTeam ?? ''), environment: String(config.configuration.tagEnvironment ?? 'dev') },
                  },
            },
          },
        ],
      },
    },
    resource_changes: [],
  }
}

export function generatePlan(config: DeployPreviewConfig): TerraformPlan {
  switch (config.resourceType) {
    case 's3':
      return planForS3(config)
    case 'ec2':
      return planForEC2(config)
    case 'rds':
      return planForRDS(config)
    case 'aks':
    case 'gke':
      return planForK8s(config)
    default:
      return planForS3(config)
  }
}
