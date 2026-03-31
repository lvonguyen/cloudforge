import { AlertTriangle, Bot, Terminal, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { Finding } from '@/types/compliance'

const FALLBACK_GUIDANCE: Record<string, { title: string; steps: string[] }> = {
  compute: {
    title: 'Compute Hardening Plan',
    steps: [
      'Restrict inbound exposure and confirm only expected ports remain reachable.',
      'Require modern metadata and instance profile controls before recycling workloads.',
      'Patch the image or base AMI in the deployment pipeline before redeploying.',
      'Rotate any credentials exposed to the affected workload and review IAM blast radius.',
    ],
  },
  storage: {
    title: 'Storage Protection Plan',
    steps: [
      'Enable encryption at rest and verify key ownership requirements.',
      'Block public access at the resource and account scope.',
      'Turn on versioning and access logging for rollback and investigation support.',
      'Review bucket or object ACLs against least-privilege access patterns.',
    ],
  },
  database: {
    title: 'Database Exposure Plan',
    steps: [
      'Move the service behind private networking and validate TLS-only access.',
      'Enable audit logging and confirm backup coverage before making changes.',
      'Rotate privileged credentials or migrate to IAM/database auth where possible.',
      'Re-run posture validation after the network and encryption controls are in place.',
    ],
  },
  network: {
    title: 'Network Containment Plan',
    steps: [
      'Remove or narrow broad ingress rules on the exposed edge.',
      'Segment the workload behind private subnets or service meshes where appropriate.',
      'Enable flow logging so repeat exposure can be correlated quickly.',
      'Validate the change against attack-path and blast-radius views after rollout.',
    ],
  },
  identity: {
    title: 'Identity Recovery Plan',
    steps: [
      'Eliminate unused principals, credentials, and trust edges related to the finding.',
      'Enforce MFA or stronger conditional access on the affected identity tier.',
      'Reduce privileges to the exact actions required for the workload.',
      'Review related roles and groups for similar drift before closing the issue.',
    ],
  },
  container: {
    title: 'Container Remediation Plan',
    steps: [
      'Rebuild from a patched base image and rescan before deployment.',
      'Confirm cluster admission or pod security controls block the same drift pattern.',
      'Move secrets out of container env vars and rotate anything exposed.',
      'Verify runtime telemetry and network policy coverage after redeploying.',
    ],
  },
  serverless: {
    title: 'Serverless Hardening Plan',
    steps: [
      'Reduce execution-role privileges and isolate private-resource access.',
      'Review environment variables for secrets or unsafe defaults.',
      'Enable trace and log coverage to capture future abuse paths.',
      'Re-test the function trigger path after deploying the guardrails.',
    ],
  },
}

export function FindingRemediationPlan({ finding }: { finding: Finding }) {
  const fallback = FALLBACK_GUIDANCE[finding.resource_type] ?? FALLBACK_GUIDANCE.compute

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <Wrench className="h-3.5 w-3.5" />
            Remediation Plan
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {finding.remediation_steps && finding.remediation_steps.length > 0 ? (
          finding.remediation_steps.map((step) => (
            <div key={step.order} className="rounded-2xl border border-border/80 bg-muted/20 p-3">
              <div className="flex items-start gap-3">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-border bg-background text-[11px] font-bold">
                  {step.order}
                </div>
                <div className="min-w-0 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold">{step.title}</p>
                    {step.automated && (
                      <Badge variant="outline" className="text-[10px] bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-800">
                        <Bot className="mr-1 h-3 w-3" />
                        Automated
                      </Badge>
                    )}
                    {step.platform && (
                      <Badge variant="outline" className="text-[10px]">{step.platform}</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{step.description}</p>
                  {step.command && (
                    <div className="rounded-xl border border-border bg-background px-3 py-2">
                      <div className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        <Terminal className="h-3 w-3" />
                        Command
                      </div>
                      <code className="block overflow-x-auto text-[11px] font-mono">{step.command}</code>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="rounded-2xl border border-border/80 bg-muted/20 p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-500" />
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-semibold">{fallback.title}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{finding.remediation}</p>
                </div>
                <ol className="space-y-2">
                  {fallback.steps.map((step, index) => (
                    <li key={step} className="flex items-start gap-2 text-sm text-muted-foreground">
                      <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-border bg-background text-[10px] font-semibold">
                        {index + 1}
                      </span>
                      <span>{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
