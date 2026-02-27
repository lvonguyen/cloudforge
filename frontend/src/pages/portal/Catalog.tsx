import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Server, Database, Box, Cloud, HardDrive } from 'lucide-react'

interface CatalogModule {
  id: string
  name: string
  description: string
  provider: string
  resource_type: string
  version: string
  cost_estimate: string
  tags: string[]
  icon: typeof Server
}

const MODULES: CatalogModule[] = [
  {
    id: 's3', name: 'S3 Object Storage', description: 'Encrypted S3 bucket with versioning, lifecycle rules, and access logging. KMS key management included.',
    provider: 'aws', resource_type: 's3', version: 'v2.4.1', cost_estimate: '$2–$50/mo',
    tags: ['storage', 'encryption', 'versioning'], icon: HardDrive,
  },
  {
    id: 'ec2', name: 'EC2 Compute Instance', description: 'Hardened EC2 instance with approved AMI, enforced instance types, security group guardrails, and SSM access.',
    provider: 'aws', resource_type: 'ec2', version: 'v3.1.0', cost_estimate: '$10–$500/mo',
    tags: ['compute', 'hardened', 'ssm'], icon: Server,
  },
  {
    id: 'rds', name: 'RDS Managed Database', description: 'PostgreSQL or MySQL RDS instance with encryption at rest, automated backups, and Multi-AZ support.',
    provider: 'aws', resource_type: 'rds', version: 'v2.2.0', cost_estimate: '$25–$300/mo',
    tags: ['database', 'encryption', 'multi-az'], icon: Database,
  },
  {
    id: 'aks', name: 'AKS Kubernetes Cluster', description: 'Azure Kubernetes Service cluster with RBAC, Azure AD integration, private API server, and policy enforcement.',
    provider: 'azure', resource_type: 'aks', version: 'v1.8.2', cost_estimate: '$50–$800/mo',
    tags: ['kubernetes', 'rbac', 'private'], icon: Box,
  },
  {
    id: 'gke', name: 'GKE Kubernetes Cluster', description: 'GKE Autopilot cluster with Workload Identity, Binary Authorization, and VPC-native networking.',
    provider: 'gcp', resource_type: 'gke', version: 'v1.6.0', cost_estimate: '$50–$800/mo',
    tags: ['kubernetes', 'autopilot', 'workload-identity'], icon: Cloud,
  },
]

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700',
  azure: 'bg-blue-100 text-blue-700',
  gcp: 'bg-green-100 text-green-700',
}

const PROVIDER_FILTER = ['ALL', 'aws', 'azure', 'gcp'] as const

export default function Catalog() {
  const navigate = useNavigate()
  const [providerFilter, setProviderFilter] = useState<string>('ALL')

  const filtered = providerFilter === 'ALL' ? MODULES : MODULES.filter(m => m.provider === providerFilter)

  function handleRequest(moduleId: string) {
    navigate('/portal/request', { state: { preselect: moduleId } })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Resource Catalog</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Terraform golden modules — policy-compliant by default</p>
      </div>

      {/* Provider filter */}
      <div className="flex gap-1 flex-wrap">
        {PROVIDER_FILTER.map(p => (
          <button
            key={p}
            onClick={() => setProviderFilter(p)}
            className={`px-3 py-1 text-xs rounded-md font-medium transition-colors ${
              providerFilter === p ? 'bg-foreground text-background' : 'bg-muted text-muted-foreground hover:bg-muted/80'
            }`}
          >
            {p === 'ALL' ? 'All Providers' : p.toUpperCase()} {p !== 'ALL' ? `(${MODULES.filter(m => m.provider === p).length})` : `(${MODULES.length})`}
          </button>
        ))}
      </div>

      {/* Module cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map(module => {
          const Icon = module.icon
          return (
            <Card key={module.id} className="hover:shadow-sm transition-shadow">
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center shrink-0">
                      <Icon className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div>
                      <CardTitle className="text-sm leading-snug">{module.name}</CardTitle>
                      <p className="text-[10px] text-muted-foreground font-mono">{module.version}</p>
                    </div>
                  </div>
                  <Badge variant="secondary" className={`text-[10px] shrink-0 ${PROVIDER_COLORS[module.provider] ?? ''}`}>
                    {module.provider.toUpperCase()}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground leading-relaxed">{module.description}</p>
                <div className="flex flex-wrap gap-1">
                  {module.tags.map(tag => (
                    <span key={tag} className="text-[10px] bg-muted rounded px-1.5 py-0.5 font-mono">{tag}</span>
                  ))}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">{module.cost_estimate}</span>
                  <Button size="sm" className="text-xs h-7" onClick={() => handleRequest(module.id)}>
                    Request
                  </Button>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
