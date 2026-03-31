import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { useForm, type FieldValues, type UseFormReturn } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { CheckCircle2 } from 'lucide-react'
import { MultiStepForm } from '@/components/portal/MultiStepForm'
import { DeployPreview } from '@/components/portal/DeployPreview'
import { ResourceSelectionStep } from '@/components/portal/request/ResourceSelectionStep'
import { ConfigurationStep } from '@/components/portal/request/ConfigurationStep'
import { PolicyValidationStep } from '@/components/portal/request/PolicyValidationStep'
import { ReviewStep } from '@/components/portal/request/ReviewStep'
import {
  REGIONS,
  MOCK_POLICY_RESULT,
  step2BaseSchema,
} from '@/components/portal/request/request-shared'
import { useCatalog } from '@/hooks/useCatalog'
import { useCreateException } from '@/hooks/useExceptions'
import { useAuth } from '@/lib/auth'
import { apiClient } from '@/lib/api'
import { useTracePanel } from '@/lib/trace-panel-context'
import type { PolicyInput, PolicyResult } from '@/types/policy'
import type { ExceptionType } from '@/types/grc'
import type { Span } from '@/types/ai-governance'

export default function Request() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user } = useAuth()
  const createException = useCreateException()
  const { data: catalogModules = [] } = useCatalog()
  const { openTimeline } = useTracePanel()

  const catalog = catalogModules.map(m => ({
    id: m.id,
    name: m.name,
    description: m.description,
    provider: m.provider,
    resourceType: m.resource_type,
    estimatedMonthlyCost: m.cost_estimate,
    icon_path: m.icon_path,
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
  const [serviceModel, setServiceModel] = useState<string>('IaaS')

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
    mode: 'onTouched',
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
      const valid = await form.trigger()
      if (!valid) return
      setConfigSnapshot(form.getValues())
      await runPolicyCheck()
    }
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

    const startTime = Date.now()
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
    const durationMs = Date.now() - startTime

    const submitSpan: Span = {
      span_id: `submit-${Date.now()}`,
      name: 'resource_request.submit',
      type: 'tool',
      status: 'ok',
      start_time: new Date(startTime).toISOString(),
      end_time: new Date().toISOString(),
      duration_ms: durationMs,
      data: {
        tool: {
          tool_name: 'createException',
          tool_category: 'grc',
          parameter_count: 4,
          external_call: true,
          input_hash: 'sha256:req-' + Date.now().toString(16),
          output_hash: 'sha256:res-' + Date.now().toString(16),
        },
      },
      events: [],
      attributes: {
        'request.resource': resource?.name ?? selectedResource,
        'request.provider': cloudProvider,
        'request.region': region,
        'request.user': user.email,
        'request.exceptions': acceptedExceptions.length,
      },
    }
    openTimeline('Resource Request Submitted', [submitSpan])

    setSubmitted(true)
    setTimeout(() => navigate('/portal/requests'), 2000)
  }

  const step1Complete = Boolean(selectedResource && cloudProvider && region && serviceModel)
  const step4CanSubmit =
    (acceptedExceptions.length === 0 || businessCase.trim().length > 0) && !createException.isPending

  const steps = [
    {
      label: 'Resource',
      content: (
        <ResourceSelectionStep
          selectedId={selectedResource}
          onSelect={id => {
            setSelectedResource(id)
            const item = catalog.find(c => c.id === id)
            if (item) {
              setCloudProvider(item.provider)
              const regions = REGIONS[item.provider] ?? []
              setRegion(regions[0] ?? '')
            }
            setTimeout(() => setCurrentStep(1), 50)
          }}
          provider={cloudProvider}
          onProviderChange={setCloudProvider}
          region={region}
          onRegionChange={setRegion}
          serviceModel={serviceModel}
          onServiceModelChange={setServiceModel}
          catalog={catalog}
        />
      ),
    },
    {
      label: 'Configuration',
      content: <ConfigurationStep resourceId={selectedResource} form={form as unknown as UseFormReturn<FieldValues>} />,
    },
    {
      label: 'Policy Check',
      content: (
        <PolicyValidationStep
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
        <ReviewStep
          step1={{ resourceId: selectedResource, cloudProvider, region, serviceModel }}
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
    <div className="space-y-4">
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
