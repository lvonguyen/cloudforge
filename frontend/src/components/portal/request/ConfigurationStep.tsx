import { Controller, type FieldValues, type UseFormReturn } from 'react-hook-form'
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
import { GENERIC_SKUS } from './request-shared'

function ResourceFields({
  resourceId,
  control,
  errors,
}: {
  resourceId: string
  control: UseFormReturn<FieldValues>['control']
  errors: Record<string, { message?: string }>
}) {
  const rid = resourceId.replace(/^(aws|azure|gcp)-/, '')
  if (rid === 'ec2') {
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
                  {['t3.micro', 't3.small', 't3.medium', 't3.large', 't3.2xlarge', 'm5.xlarge'].map((value) => (
                    <SelectItem key={value} value={value}>{value}</SelectItem>
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

  if (rid === 's3') {
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
            <input type="checkbox" id="versioning" checked={field.value as boolean} onChange={(e) => field.onChange(e.target.checked)} className="h-4 w-4 rounded border-input" />
          )} />
          <Label htmlFor="versioning" className="cursor-pointer">Enable versioning</Label>
        </div>
      </>
    )
  }

  if (rid === 'rds') {
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
                {['db.t3.micro', 'db.t3.medium', 'db.t3.large', 'db.r5.large', 'db.r5.2xlarge'].map((value) => (
                  <SelectItem key={value} value={value}>{value}</SelectItem>
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

  if (rid === 'aks' || rid === 'eks' || rid === 'gke') {
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
                {['Standard_D2s_v3', 'Standard_D4s_v3', 'n1-standard-2', 'n1-standard-4', 'e2-standard-4'].map((value) => (
                  <SelectItem key={value} value={value}>{value}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )} />
        </div>
        <div className="flex items-center gap-2">
          <Controller name="autoscaling" control={control} defaultValue={true} render={({ field }) => (
            <input type="checkbox" id="autoscaling" checked={field.value as boolean} onChange={(e) => field.onChange(e.target.checked)} className="h-4 w-4 rounded border-input" />
          )} />
          <Label htmlFor="autoscaling" className="cursor-pointer">Enable autoscaling</Label>
        </div>
      </>
    )
  }

  return (
    <>
      <div className="space-y-1.5 sm:col-span-2">
        <Label>Size / SKU</Label>
        <Controller name="sku" control={control} defaultValue="medium" render={({ field }) => (
          <Select value={field.value as string} onValueChange={field.onChange}>
            <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
            <SelectContent>
              {GENERIC_SKUS.map((sku) => (
                <SelectItem key={sku.id} value={sku.id}>
                  <span className="font-medium">{sku.name}</span>
                  <span className="ml-2 text-muted-foreground">— {sku.description} ({sku.cost})</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )} />
      </div>
      <div className="space-y-1.5">
        <Label>Name / Identifier</Label>
        <Controller name="resourceName" control={control} defaultValue="" render={({ field }) => (
          <Input {...field} placeholder={`my-${rid || 'resource'}`} />
        )} />
      </div>
    </>
  )
}

export function ConfigurationStep({
  resourceId,
  form,
}: {
  resourceId: string
  form: UseFormReturn<FieldValues>
}) {
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
