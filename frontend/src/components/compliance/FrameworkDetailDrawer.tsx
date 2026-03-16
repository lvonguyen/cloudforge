import { useMemo } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, ExternalLink } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { ComplianceScore } from './ComplianceScore'

interface Category {
  id: string
  name: string
  passing: number
  failing: number
  score: number
}

interface Framework {
  id: string
  name: string
  description: string
  total_controls: number
  controls_passing: number
  controls_failing: number
  score: number
  category: string
  categories?: Category[]
}

interface Control {
  id: string
  title: string
  category: string
  status: 'pass' | 'fail'
}

function generateControls(fw: Framework): Control[] {
  const controls: Control[] = []
  const cats = fw.categories ?? []

  for (const cat of cats) {
    for (let i = 1; i <= cat.passing; i++) {
      controls.push({
        id: `${cat.id}-${String(i).padStart(2, '0')}`,
        title: `${cat.name} — Control ${i}`,
        category: cat.name,
        status: 'pass',
      })
    }
    for (let i = 1; i <= cat.failing; i++) {
      controls.push({
        id: `${cat.id}-F${String(i).padStart(2, '0')}`,
        title: `${cat.name} — Control ${cat.passing + i}`,
        category: cat.name,
        status: 'fail',
      })
    }
  }

  return controls
}

export function FrameworkDetailDrawer({
  framework,
  open,
  onOpenChange,
  docLink,
}: {
  framework: Framework | null
  open: boolean
  onOpenChange: (open: boolean) => void
  docLink?: string
}) {
  const controls = useMemo(
    () => (framework ? generateControls(framework) : []),
    [framework],
  )

  if (!framework) return null

  const cats = framework.categories ?? []

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="sm:max-w-lg w-full overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="text-base">{framework.name}</SheetTitle>
          <SheetDescription>{framework.description}</SheetDescription>
          {docLink && (
            <a
              href={docLink}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-xs text-primary hover:underline mt-1"
            >
              <ExternalLink className="h-3 w-3" />View Documentation
            </a>
          )}
        </SheetHeader>

        <div className="px-4 pb-6 space-y-5">
          {/* Overall score */}
          <div className="flex items-center justify-between">
            <ComplianceScore score={framework.score} />
            <span className="text-xs text-muted-foreground">
              {framework.controls_passing}/{framework.total_controls} controls passing
            </span>
          </div>

          {/* Category breakdown */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Categories</h3>
            {cats.map(cat => (
              <div key={cat.id} className="flex items-center justify-between text-sm">
                <span>{cat.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">
                    {cat.passing}/{cat.passing + cat.failing}
                  </span>
                  <Badge
                    variant="secondary"
                    className={`text-[10px] px-1.5 py-0 ${
                      cat.score >= 90
                        ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                        : cat.score >= 75
                          ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                          : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                    }`}
                  >
                    {cat.score.toFixed(0)}%
                  </Badge>
                </div>
              </div>
            ))}
          </div>

          {/* Controls table */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Controls ({controls.length})
            </h3>
            <div className="border rounded-none divide-y max-h-[400px] overflow-y-auto">
              {controls.map(ctrl => (
                <div key={ctrl.id} className="flex items-center gap-2 px-3 py-2 text-xs">
                  {ctrl.status === 'pass' ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-green-600 shrink-0" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-red-600 shrink-0" />
                  )}
                  <span className="font-mono text-muted-foreground shrink-0">{ctrl.id}</span>
                  <span className="truncate">{ctrl.title}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Failing controls summary */}
          {framework.controls_failing > 0 && (
            <div className="rounded-none border border-red-200 bg-red-50 dark:bg-red-900/10 dark:border-red-800 p-3 space-y-1">
              <div className="flex items-center gap-1.5 text-sm font-medium text-red-800 dark:text-red-300">
                <AlertTriangle className="h-3.5 w-3.5" />
                {framework.controls_failing} failing control{framework.controls_failing > 1 ? 's' : ''}
              </div>
              <p className="text-xs text-red-700 dark:text-red-400">
                Review failing controls and create remediation tasks to improve compliance posture.
              </p>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
