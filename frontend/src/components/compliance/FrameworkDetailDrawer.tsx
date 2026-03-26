import { useState } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet'
import { Badge } from '@/components/ui/badge'
import { ComplianceScore } from './ComplianceScore'

interface ControlDetail {
  id: string
  title: string
  status: 'pass' | 'fail'
  description?: string
  finding_count?: number
  citation?: string
  reference_url?: string
}

interface Category {
  id: string
  name: string
  passing: number
  failing: number
  score: number
  controls?: ControlDetail[]
}

interface FrameworkScope {
  environments: number
  prod_environments: number
  lines_of_business: number
  csp_sources: string[]
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
  scope?: FrameworkScope
}

// generateControls creates placeholder controls from category stats when
// real control data is not available in the JSON.
function generateControls(cat: Category): ControlDetail[] {
  const controls: ControlDetail[] = []
  for (let i = 1; i <= cat.passing; i++) {
    controls.push({
      id: `${cat.id}-${String(i).padStart(2, '0')}`,
      title: `${cat.name} — Control ${i}`,
      status: 'pass',
    })
  }
  for (let i = 1; i <= cat.failing; i++) {
    controls.push({
      id: `${cat.id}-F${String(i).padStart(2, '0')}`,
      title: `${cat.name} — Control ${cat.passing + i}`,
      status: 'fail',
    })
  }
  return controls
}

function CategoryAccordion({ cat, frameworkId }: { cat: Category; frameworkId: string }) {
  const [expanded, setExpanded] = useState(false)
  const [expandedControl, setExpandedControl] = useState<string | null>(null)
  const navigate = useNavigate()
  const controls = cat.controls ?? generateControls(cat)

  return (
    <div className="border rounded-sm">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between w-full px-3 py-2 text-sm hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          <span className="font-medium">{cat.name}</span>
        </div>
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
      </button>

      {expanded && (
        <div className="border-t divide-y">
          {controls.map(ctrl => (
            <div key={ctrl.id} className="px-3 py-2 text-xs">
              <div
                className="flex items-center gap-2 cursor-pointer"
                onClick={() => setExpandedControl(expandedControl === ctrl.id ? null : ctrl.id)}
              >
                {ctrl.status === 'pass' ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-green-600 shrink-0" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-red-600 shrink-0" />
                )}
                <span className="font-mono text-muted-foreground shrink-0">{ctrl.id}</span>
                <div className="flex-1 min-w-0">
                  <span className="truncate block">{ctrl.title}</span>
                  {ctrl.description && expandedControl !== ctrl.id && (
                    <span className="text-[10px] text-muted-foreground truncate block">{ctrl.description}</span>
                  )}
                </div>
                {ctrl.status === 'fail' && (ctrl.finding_count ?? 0) > 0 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      navigate(`/ops/findings?framework=${frameworkId}&control=${ctrl.id}`)
                    }}
                    className="text-[10px] text-primary hover:underline shrink-0"
                  >
                    {ctrl.finding_count} finding{ctrl.finding_count! > 1 ? 's' : ''}
                  </button>
                )}
              </div>
              {expandedControl === ctrl.id && (
                <div className="ml-5 mt-2 space-y-1.5 border-l-2 border-muted pl-3">
                  {ctrl.description && (
                    <p className="text-[10px] text-muted-foreground">{ctrl.description}</p>
                  )}
                  {ctrl.citation && (
                    <div className="bg-muted/30 px-2 py-1.5">
                      <p className="text-[10px] text-muted-foreground italic">{ctrl.citation}</p>
                    </div>
                  )}
                  {ctrl.reference_url?.startsWith('https://') && (
                    <a
                      href={ctrl.reference_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] text-primary hover:underline"
                    >
                      <ExternalLink className="h-2.5 w-2.5" />View Standard
                    </a>
                  )}
                  {ctrl.status === 'fail' && (
                    <button
                      onClick={() => navigate(`/ops/findings?framework=${frameworkId}&control=${ctrl.id}`)}
                      className="text-[10px] text-primary hover:underline block"
                    >
                      View related findings →
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
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
  if (!framework) return null

  const cats = framework.categories ?? []

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="sm:max-w-lg w-full overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="text-base">{framework.name}</SheetTitle>
          <SheetDescription>{framework.description}</SheetDescription>
          {docLink?.startsWith('https://') && (
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

          {/* Scope annotation */}
          {framework.scope && (
            <div className="grid grid-cols-2 gap-3 rounded-sm border border-border p-3">
              <div>
                <p className="text-[10px] text-muted-foreground">Environments</p>
                <p className="text-sm font-semibold tabular-nums">{framework.scope.environments}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">Production</p>
                <p className="text-sm font-semibold tabular-nums">{framework.scope.prod_environments}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">Lines of Business</p>
                <p className="text-sm font-semibold tabular-nums">{framework.scope.lines_of_business}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">CSP Sources</p>
                <p className="text-sm font-semibold">{(framework.scope.csp_sources ?? []).map(s => s.toUpperCase()).join(', ') || '\u2014'}</p>
              </div>
            </div>
          )}

          {/* Category accordions with inline controls */}
          <div className="space-y-1.5">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Categories & Controls
            </p>
            {cats.map(cat => (
              <CategoryAccordion key={cat.id} cat={cat} frameworkId={framework.id} />
            ))}
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
