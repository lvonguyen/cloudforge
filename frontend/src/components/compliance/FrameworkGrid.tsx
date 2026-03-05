import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ComplianceScore } from './ComplianceScore'

interface Framework {
  id: string
  name: string
  description: string
  total_controls: number
  controls_passing: number
  controls_failing: number
  score: number
  category: string
}

const CATEGORY_COLORS: Record<string, string> = {
  security: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  compliance: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  'ai-governance': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  automotive: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
}

export function FrameworkGrid({ frameworks }: { frameworks: Framework[] }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {frameworks.map(fw => (
        <Card key={fw.id} className="hover:shadow-sm transition-shadow">
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-2">
              <CardTitle className="text-sm">{fw.name}</CardTitle>
              <Badge variant="secondary" className={`text-[10px] shrink-0 ${CATEGORY_COLORS[fw.category] ?? ''}`}>
                {fw.category}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            <ComplianceScore score={fw.score} />
            <div className="w-full bg-muted rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${fw.score >= 90 ? 'bg-green-500 dark:bg-green-400' : fw.score >= 75 ? 'bg-yellow-500 dark:bg-yellow-400' : 'bg-red-500 dark:bg-red-400'}`}
                style={{ width: `${fw.score}%` }}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              {fw.controls_passing}/{fw.total_controls} controls passing · {fw.controls_failing} failing
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
