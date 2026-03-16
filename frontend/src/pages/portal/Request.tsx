import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useForm, Controller, type UseFormReturn, type FieldValues } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { Loader2, CheckCircle2 } from 'lucide-react'
import { MultiStepForm } from '@/components/portal/MultiStepForm'
import { DeployPreview } from '@/components/portal/DeployPreview'
import { PolicyCheckResult } from '@/components/portal/PolicyCheckResult'
import { ResourceCatalogCard } from '@/components/portal/ResourceCatalogCard'
import { useCatalog } from '@/hooks/useCatalog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { useCreateException } from '@/hooks/useExceptions'
import { useAuth } from '@/lib/auth'
import { apiClient } from '@/lib/api'
import type { PolicyInput, PolicyResult } from '@/types/policy'
import type { ExceptionType } from '@/types/grc'

// ── Catalog (dynamic) ────────────────────────────────────────────────────────

const REGIONS: Record<string, string[]> = {
  aws: ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1'],
  azure: ['eastus', 'westus2', 'westeurope', 'southeastasia'],
  gcp: ['us-central1', 'us-east1', 'europe-west1', 'asia-southeast1'],
}

// ── Zod schemas ─────────────────────────────────────────────────────────────

const step1Schema = z.object({
  resourceId: z.string().min(1, 'Select a resource type'),
  cloudProvider: z.string().min(1, 'Select a cloud provider'),
  region: z.string().min(1, 'Select a region'),
})

const step2BaseSchema = z.object({
  applicationId: z.string().min(1, 'Application ID is required'),
  tagTeam: z.string().min(1, 'Team tag is required'),
  tagCostCenter: z.string().min(1, 'Cost center is required'),
  tagEnvironment: z.enum(['dev', 'staging', 'prod']),
})

type Step1Values = z.infer<typeof step1Schema>

// ── Mock policy result ───────────────────────────────────────────────────────

const MOCK_POLICY_RESULT: PolicyResult = {
  allowed: false,
  denials: [
    {
      code: 'REGION-001',
      message: 'ap-southeast-3 not in approved regions',
      severity: 'high',
      remediation: 'Use us-east-1, eu-west-1, or ap-southeast-1',
    },
  ],
  warnings: [
    {
      code: 'COST-002',
      message: 't3.2xlarge exceeds standard size (t3.large)',
      severity: 'medium',
      remediation: 'Requires business justification + manager approval',
    },
  ],
  suggestions: ['Add required tags: team, cost-center'],
}

// ── Step 1: Resource Selection ───────────────────────────────────────────────

function StepResourceSelection({
  selectedId,
  onSelect,
  provider,
  onProviderChange,
  region,
  onRegionChange,
  catalog,
}: {
  selectedId: string
  onSelect: (id: string) => void
  provider: string
  onProviderChange: (p: string) => void
  region: string
  onRegionChange: (r: string) => void
  catalog: { id: string; name: string; description: string; provider: string; resourceType: string; estimatedMonthlyCost: string }[]
}) {
  const regions = REGIONS[provider] ?? []

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-semibold mb-3">Select Resource Type</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {catalog.map(item => (
            <div
              key={item.id}
              className={`cursor-pointer rounded-none ring-2 transition-all ${
                selectedId === item.id ? 'ring-primary' : 'ring-transparent hover:ring-muted-foreground/30'
              }`}
              onClick={() => {
                onSelect(item.id)
                onProviderChange(item.provider)
              }}
            >
              <ResourceCatalogCard item={item} />
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label>Cloud Provider</Label>
          <Select value={provider} onValueChange={onProviderChange}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select provider" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="aws">AWS</SelectItem>
              <SelectItem value="azure">Azure</SelectItem>
              <SelectItem value="gcp">GCP</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Region</Label>
          <Select value={region} onValueChange={onRegionChange} disabled={!provider}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select region" />
            </SelectTrigger>
            <SelectContent>
              {regions.map(r => (
                <SelectItem key={r} value={r}>{r}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  )
}

// ── Step 2: Configuration ────────────────────────────────────────────────────

function ResourceFields({ resourceId, control, errors }: { resourceId: string; control: UseFormReturn<FieldValues>['control']; errors: Record<string, { message?: string }> }) {
  if (resourceId === 'ec2') {
    return (
      <>
        <div className="space-y-1.5">
          <Label>Instance Type</Label>
          <Controller
            name="instanceType"
            control={control}
            defaultValue="t3.medium"
            render={({ field }) => (
              <Select value={field.value as string} onValueChange={field.onChange}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {['t3.micro', 't3.small', 't3.medium', 't3.large', 't3.2xlarge', 'm5.xlarge'].map(t => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          />
        </div>
        <div className="space-y-1.5">
          <Label>AMI ID</Label>
          <Controller name="amiId" control={control} defaultValue="" render={({ field }) => (
            <Input {...field} placeholder="ami-0abcdef1234567890" />
          )} />
          {errors.amiId && <p className="text-xs text-destructive">{errors.amiId.message}</p>}
        </div>
        <div className="space-y-1.5">
          <Label>Subnet ID</Label>
          <Controller name="subnetId" control={control} defaultValue="" render={({ field }) => (
            <Input {...field} placeholder="subnet-0abc1234" />
          )} />
          {errors.subnetId && <p className="text-xs text-destructive">{errors.subnetId.message}</p>}
        </div>
      </>
    )
  }

  if (resourceId === 's3') {
    return (
      <>
        <div className="space-y-1.5">
          <Label>Bucket Name</Label>
          <Controller name="bucketName" control={control} defaultValue="" render={({ field }) => (
            <Input {...field} placeholder="my-app-bucket" />
          )} />
          {errors.bucketName && <p className="text-xs text-destructive">{errors.bucketName.message}</p>}
        </div>
        <div className="space-y-1.5">
          <Label>Encryption</Label>
          <Controller name="encryption" control={control} defaultValue="AES256" render={({ field }) => (
            <Select value={field.value as string} onValueChange={field.onChange}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="AES256">AES-256</SelectItem>
                <SelectItem value="KMS">KMS</SelectItem>
              </SelectContent>
            </Select>
          )} />
        </div>
        <div className="flex items-center gap-2">
          <Controller name="versioning" control={control} defaultValue={false} render={({ field }) => (
            <input type="checkbox" id="versioning" checked={field.value as boolean} onChange={e => field.onChange(e.target.checked)} className="h-4 w-4 rounded border-input" />
          )} />
          <Label htmlFor="versioning" className="cursor-pointer">Enable versioning</Label>
        </div>
      </>
    )
  }

  if (resourceId === 'rds') {
    return (
      <>
        <div className="space-y-1.5">
          <Label>Engine</Label>
          <Controller name="engine" control={control} defaultValue="postgres" render={({ field }) => (
            <Select value={field.value as string} onValueChange={field.onChange}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="postgres">PostgreSQL</SelectItem>
                <SelectItem value="mysql">MySQL</SelectItem>
              </SelectContent>
            </Select>
          )} />
        </div>
        <div className="space-y-1.5">
          <Label>Instance Class</Label>
          <Controller name="instanceClass" control={control} defaultValue="db.t3.medium" render={({ field }) => (
            <Select value={field.value as string} onValueChange={field.onChange}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {['db.t3.micro', 'db.t3.medium', 'db.t3.large', 'db.r5.large', 'db.r5.2xlarge'].map(c => (
                  <SelectItem key={c} value={c}>{c}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )} />
        </div>
        <div className="space-y-1.5">
          <Label>Storage (GB)</Label>
          <Controller name="storageGb" control={control} defaultValue={20} render={({ field }) => (
            <Input type="number" {...field} min={20} />
          )} />
          {errors.storageGb && <p className="text-xs text-destructive">{errors.storageGb.message}</p>}
        </div>
      </>
    )
  }

  // AKS or GKE
  return (
    <>
      <div className="space-y-1.5">
        <Label>Node Count</Label>
        <Controller name="nodeCount" control={control} defaultValue={3} render={({ field }) => (
          <Input type="number" {...field} min={1} max={100} />
        )} />
        {errors.nodeCount && <p className="text-xs text-destructive">{errors.nodeCount.message}</p>}
      </div>
      <div className="space-y-1.5">
        <Label>Machine Type</Label>
        <Controller name="machineType" control={control} defaultValue="" render={({ field }) => (
          <Select value={field.value as string} onValueChange={field.onChange}>
            <SelectTrigger className="w-full"><SelectValue placeholder="Select type" /></SelectTrigger>
            <SelectContent>
              {['Standard_D2s_v3', 'Standard_D4s_v3', 'n1-standard-2', 'n1-standard-4', 'e2-standard-4'].map(m => (
                <SelectItem key={m} value={m}>{m}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )} />
      </div>
      <div className="flex items-center gap-2">
        <Controller name="autoscaling" control={control} defaultValue={true} render={({ field }) => (
          <input type="checkbox" id="autoscaling" checked={field.value as boolean} onChange={e => field.onChange(e.target.checked)} className="h-4 w-4 rounded border-input" />
        )} />
        <Label htmlFor="autoscaling" className="cursor-pointer">Enable autoscaling</Label>
      </div>
    </>
  )
}

function StepConfiguration({ resourceId, form }: { resourceId: string; form: UseFormReturn<FieldValues> }) {
  const { control, formState: { errors } } = form
  const typedErrors = errors as Record<string, { message?: string }>

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <ResourceFields resourceId={resourceId} control={control} errors={typedErrors} />
      </div>

      <Separator />

      <div className="space-y-3">
        <h3 className="text-sm font-semibold">Application & Tags</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5 sm:col-span-2">
            <Label>Application ID <span className="text-destructive">*</span></Label>
            <Controller name="applicationId" control={control} defaultValue="" render={({ field }) => (
              <Input {...field} placeholder="app-001" />
            )} />
            {typedErrors.applicationId && <p className="text-xs text-destructive">{typedErrors.applicationId.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Team <span className="text-destructive">*</span></Label>
            <Controller name="tagTeam" control={control} defaultValue="" render={({ field }) => (
              <Input {...field} placeholder="platform-eng" />
            )} />
            {typedErrors.tagTeam && <p className="text-xs text-destructive">{typedErrors.tagTeam.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Cost Center <span className="text-destructive">*</span></Label>
            <Controller name="tagCostCenter" control={control} defaultValue="" render={({ field }) => (
              <Input {...field} placeholder="CC-1234" />
            )} />
            {typedErrors.tagCostCenter && <p className="text-xs text-destructive">{typedErrors.tagCostCenter.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label>Environment</Label>
            <Controller name="tagEnvironment" control={control} defaultValue="dev" render={({ field }) => (
              <Select value={field.value as string} onValueChange={field.onChange}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="dev">dev</SelectItem>
                  <SelectItem value="staging">staging</SelectItem>
                  <SelectItem value="prod">prod</SelectItem>
                </SelectContent>
              </Select>
            )} />
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Step 3: Policy Validation ────────────────────────────────────────────────

function StepPolicyValidation({
  policyResult,
  isLoading,
  acceptedExceptions,
  onAcceptException,
}: {
  policyResult: PolicyResult | null
  isLoading: boolean
  acceptedExceptions: string[]
  onAcceptException: (code: string) => void
}) {
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-12 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin" />
        <p className="text-sm">Running policy validation...</p>
      </div>
    )
  }

  if (!policyResult) {
    return <p className="text-sm text-muted-foreground">Policy check not yet run.</p>
  }

  return (
    <div className="space-y-4">
      <PolicyCheckResult
        result={policyResult}
        onRequestException={code => onAcceptException(code)}
      />
      {acceptedExceptions.length > 0 && (
        <div className="rounded-none border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
          <p className="font-medium">Exception requests queued ({acceptedExceptions.length})</p>
          <ul className="mt-1 list-disc pl-4 text-xs">
            {acceptedExceptions.map(code => <li key={code}>{code}</li>)}
          </ul>
          <p className="mt-1 text-xs opacity-80">Provide business justification in the next step.</p>
        </div>
      )}
    </div>
  )
}

// ── Step 4: Review & Submit ──────────────────────────────────────────────────

function StepReview({
  step1,
  formValues,
  policyResult,
  acceptedExceptions,
  businessCase,
  onBusinessCaseChange,
  catalog,
}: {
  step1: Step1Values
  formValues: Record<string, unknown>
  policyResult: PolicyResult | null
  acceptedExceptions: string[]
  businessCase: string
  onBusinessCaseChange: (v: string) => void
  catalog: { id: string; name: string; description: string }[]
}) {
  const resource = catalog.find(c => c.id === step1.resourceId)
  const needsBusinessCase = acceptedExceptions.length > 0

  return (
    <div className="space-y-5">
      <div className="rounded-none border p-4 space-y-3">
        <h3 className="text-sm font-semibold">Request Summary</h3>
        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <span className="text-muted-foreground">Resource</span>
          <span>{resource?.name} — {resource?.description}</span>
          <span className="text-muted-foreground">Provider</span>
          <span className="uppercase">{step1.cloudProvider}</span>
          <span className="text-muted-foreground">Region</span>
          <span>{step1.region}</span>
          <span className="text-muted-foreground">Application ID</span>
          <span>{String(formValues.applicationId ?? '')}</span>
          <span className="text-muted-foreground">Team</span>
          <span>{String(formValues.tagTeam ?? '')}</span>
          <span className="text-muted-foreground">Cost Center</span>
          <span>{String(formValues.tagCostCenter ?? '')}</span>
          <span className="text-muted-foreground">Environment</span>
          <span>{String(formValues.tagEnvironment ?? '')}</span>
        </div>
      </div>

      {policyResult && (
        <div className="rounded-none border p-4 space-y-2">
          <h3 className="text-sm font-semibold">Policy Check</h3>
          {policyResult.allowed && acceptedExceptions.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-green-700">
              <CheckCircle2 className="h-4 w-4" />
              <span>All checks passed</span>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {acceptedExceptions.length} exception(s) requested: {acceptedExceptions.join(', ')}
            </p>
          )}
        </div>
      )}

      {needsBusinessCase && (
        <div className="space-y-1.5">
          <Label>Business Case <span className="text-destructive">*</span></Label>
          <textarea
            value={businessCase}
            onChange={e => onBusinessCaseChange(e.target.value)}
            placeholder="Explain why this exception is needed and how risk will be mitigated..."
            rows={4}
            className="w-full rounded-none border border-input bg-transparent px-3 py-2 text-sm shadow-xs transition-[color,box-shadow] outline-none resize-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
          />
          {!businessCase.trim() && (
            <p className="text-xs text-destructive">Business case required when requesting exceptions</p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function Request() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user } = useAuth()
  const createException = useCreateException()
  const { data: catalogModules = [] } = useCatalog()

  // Map CatalogModule[] to the shape used by ResourceCatalogCard and step components
  const catalog = catalogModules.map(m => ({
    id: m.id,
    name: m.name,
    description: m.description,
    provider: m.provider,
    resourceType: m.resource_type,
    estimatedMonthlyCost: m.cost_estimate,
  }))

  const [currentStep, setCurrentStep] = useState(0)
  const [submitted, setSubmitted] = useState(false)

  // Pre-fill from Catalog navigation
  const preselect = (location.state as { preselect?: string } | null)?.preselect
  const preselectItem = preselect ? catalog.find(c => c.id === preselect) : undefined

  // Step 1 state
  const [selectedResource, setSelectedResource] = useState<string>(preselectItem?.id ?? '')
  const [cloudProvider, setCloudProvider] = useState<string>(preselectItem?.provider ?? 'aws')
  const [region, setRegion] = useState<string>(() => {
    if (preselectItem) {
      const regions = REGIONS[preselectItem.provider] ?? []
      return regions[0] ?? ''
    }
    return ''
  })

  // Step 2 snapshot — captured when leaving Configuration step
  const [configSnapshot, setConfigSnapshot] = useState<Record<string, unknown>>({})

  // Step 3 state
  const [policyResult, setPolicyResult] = useState<PolicyResult | null>(null)
  const [policyLoading, setPolicyLoading] = useState(false)
  const [acceptedExceptions, setAcceptedExceptions] = useState<string[]>([])

  // Step 4 state
  const [businessCase, setBusinessCase] = useState('')

  const form = useForm({
    resolver: zodResolver(step2BaseSchema),
    defaultValues: {
      applicationId: '',
      tagTeam: '',
      tagCostCenter: '',
      tagEnvironment: 'dev' as const,
    },
  })

  const formValues = form.watch()

  // Auto-set region when provider changes
  useEffect(() => {
    const providerRegions = REGIONS[cloudProvider] ?? []
    if (!providerRegions.includes(region)) {
      setRegion(providerRegions[0] ?? '')
    }
  }, [cloudProvider, region])

  const runPolicyCheck = async () => {
    setPolicyLoading(true)
    const input: PolicyInput = {
      application_id: String(formValues.applicationId),
      resource_type: selectedResource,
      cloud_provider: cloudProvider,
      region,
      configuration: { ...formValues },
      tags: {
        team: String(formValues.tagTeam),
        'cost-center': String(formValues.tagCostCenter),
        environment: String(formValues.tagEnvironment),
      },
      requested_by: user.email,
    }
    try {
      const result = await apiClient.post<PolicyResult>('/validate/exception', input)
      setPolicyResult(result)
    } catch {
      setPolicyResult(MOCK_POLICY_RESULT)
    } finally {
      setPolicyLoading(false)
    }
  }

  const handleNext = async () => {
    if (currentStep === 1) {
      // Validate required fields before leaving Configuration step
      const valid = await form.trigger()
      if (!valid) return
      // Snapshot form values before leaving Configuration step
      setConfigSnapshot(form.getValues())
      // Entering policy check — run validation
      await runPolicyCheck()
    }
    // Keep snapshot fresh on forward navigation from any step after Configuration
    if (currentStep > 1) {
      setConfigSnapshot(prev => ({ ...prev, ...form.getValues() }))
    }
    setCurrentStep(s => s + 1)
  }

  const handlePrev = () => setCurrentStep(s => s - 1)

  const handleAcceptException = (code: string) => {
    setAcceptedExceptions(prev =>
      prev.includes(code) ? prev.filter(c => c !== code) : [...prev, code]
    )
  }

  const handleSubmit = async () => {
    const resource = catalog.find(c => c.id === selectedResource)
    const knownTypes: ExceptionType[] = ['UNAPPROVED_REGION', 'OVERSIZED_INSTANCE', 'RESTRICTED_SERVICE', 'NETWORK_EXPOSURE', 'DATA_RESIDENCY', 'OTHER']
    const exceptionType: ExceptionType = acceptedExceptions.length > 0
      ? (knownTypes.includes(acceptedExceptions[0] as ExceptionType) ? acceptedExceptions[0] as ExceptionType : 'OTHER')
      : 'OTHER'

    await createException.mutateAsync({
      application_id: String(formValues.applicationId),
      requestor_email: user.email,
      request_type: exceptionType,
      policy_violated: acceptedExceptions.join(', '),
      resource_requested: `${resource?.name ?? selectedResource} in ${region}`,
      business_case: businessCase || 'Standard resource request',
      status: 'PENDING',
      approver_chain: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })

    setSubmitted(true)
    setTimeout(() => navigate('/portal/requests'), 2000)
  }

  const step1Complete = Boolean(selectedResource && cloudProvider && region)
  const step4CanSubmit =
    (acceptedExceptions.length === 0 || businessCase.trim().length > 0) && !createException.isPending

  const steps = [
    {
      label: 'Resource',
      content: (
        <StepResourceSelection
          selectedId={selectedResource}
          onSelect={id => {
            setSelectedResource(id)
            const item = catalog.find(c => c.id === id)
            if (item) {
              setCloudProvider(item.provider)
              const regions = REGIONS[item.provider] ?? []
              setRegion(regions[0] ?? '')
            }
          }}
          provider={cloudProvider}
          onProviderChange={setCloudProvider}
          region={region}
          onRegionChange={setRegion}
          catalog={catalog}
        />
      ),
    },
    {
      label: 'Configuration',
      content: <StepConfiguration resourceId={selectedResource} form={form as unknown as UseFormReturn<FieldValues>} />,
    },
    {
      label: 'Policy Check',
      content: (
        <StepPolicyValidation
          policyResult={policyResult}
          isLoading={policyLoading}
          acceptedExceptions={acceptedExceptions}
          onAcceptException={handleAcceptException}
        />
      ),
    },
    {
      label: 'Deploy Preview',
      content: (
        <DeployPreview
          config={{
            resourceType: selectedResource,
            provider: cloudProvider,
            region,
            appId: String(configSnapshot.applicationId || formValues.applicationId || 'demo'),
            configuration: { ...configSnapshot, ...formValues } as Record<string, unknown>,
          }}
        />
      ),
    },
    {
      label: 'Review',
      content: (
        <StepReview
          step1={{ resourceId: selectedResource, cloudProvider, region }}
          formValues={{ ...formValues, ...configSnapshot }}
          policyResult={policyResult}
          acceptedExceptions={acceptedExceptions}
          businessCase={businessCase}
          onBusinessCaseChange={setBusinessCase}
          catalog={catalog}
        />
      ),
    },
  ]

  if (submitted) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
        <CheckCircle2 className="h-12 w-12 text-green-500" />
        <h2 className="text-lg font-semibold">Request Submitted</h2>
        <p className="text-sm text-muted-foreground">Redirecting to your requests...</p>
      </div>
    )
  }

  const canProceedMap: Record<number, boolean> = {
    0: step1Complete,
    1: true,
    2: true,
    3: true,
    4: step4CanSubmit,
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <div>
        <h1 className="text-xl font-semibold">New Resource Request</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Request cloud resources with automated OPA policy validation.
        </p>
      </div>

      <MultiStepForm
        steps={steps}
        currentStep={currentStep}
        onNext={handleNext}
        onPrev={handlePrev}
        onCancel={() => navigate('/portal')}
        onSubmit={handleSubmit}
        isSubmitting={createException.isPending}
        canProceed={canProceedMap[currentStep] ?? true}
      />
    </div>
  )
}
