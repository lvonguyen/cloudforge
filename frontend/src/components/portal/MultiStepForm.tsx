import { type ReactNode } from 'react'
import { Check } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface Step {
  label: string
  content: ReactNode
}

interface Props {
  steps: Step[]
  currentStep: number
  onNext: () => void
  onPrev: () => void
  onCancel: () => void
  onSubmit: () => void
  isSubmitting?: boolean
  canProceed?: boolean
}

export function MultiStepForm({
  steps,
  currentStep,
  onNext,
  onPrev,
  onCancel,
  onSubmit,
  isSubmitting = false,
  canProceed = true,
}: Props) {
  const isFirst = currentStep === 0
  const isLast = currentStep === steps.length - 1

  return (
    <div className="space-y-6">
      {/* Step indicator */}
      <nav aria-label="Form progress">
        <ol className="flex items-center gap-0">
          {steps.map((step, idx) => {
            const isComplete = idx < currentStep
            const isActive = idx === currentStep

            return (
              <li key={idx} className="flex flex-1 items-center">
                <div className="flex flex-col items-center gap-1 min-w-0">
                  <div
                    className={cn(
                      'flex h-8 w-8 items-center justify-center rounded-full border-2 text-xs font-semibold transition-colors shrink-0',
                      isComplete && 'border-primary bg-primary text-primary-foreground',
                      isActive && 'border-primary bg-background text-primary',
                      !isComplete && !isActive && 'border-muted-foreground/30 bg-background text-muted-foreground/50',
                    )}
                  >
                    {isComplete ? <Check className="h-4 w-4" /> : <span>{idx + 1}</span>}
                  </div>
                  <span
                    className={cn(
                      'text-[10px] font-medium text-center leading-tight px-1 truncate max-w-[72px]',
                      isActive ? 'text-primary' : 'text-muted-foreground',
                    )}
                  >
                    {step.label}
                  </span>
                </div>
                {idx < steps.length - 1 && (
                  <div
                    className={cn(
                      'h-0.5 flex-1 mx-1 mb-4 transition-colors',
                      idx < currentStep ? 'bg-primary' : 'bg-muted-foreground/20',
                    )}
                  />
                )}
              </li>
            )
          })}
        </ol>
      </nav>

      {/* Step content */}
      <div className="min-h-[300px]">{steps[currentStep]?.content}</div>

      {/* Navigation buttons */}
      <div className="flex items-center justify-between border-t pt-4">
        <Button variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <div className="flex gap-2">
          {!isFirst && (
            <Button variant="outline" size="sm" onClick={onPrev}>
              Previous
            </Button>
          )}
          {isLast ? (
            <Button size="sm" onClick={onSubmit} disabled={isSubmitting || !canProceed}>
              {isSubmitting ? 'Submitting...' : 'Submit Request'}
            </Button>
          ) : (
            <Button size="sm" onClick={onNext} disabled={!canProceed}>
              Next
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
