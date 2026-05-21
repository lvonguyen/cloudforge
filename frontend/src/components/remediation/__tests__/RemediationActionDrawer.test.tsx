import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { RemediationActionDrawer, type DrawerContext } from '../RemediationActionDrawer'
import {
  buildCandidateForFinding,
  buildCandidateForRemediation,
  buildCandidatesForNode,
} from '@/lib/remediation-catalog'
import type { Finding } from '@/types/compliance'
import type { RemediationRecord } from '@/types/remediation'
import type { AttackPath, AttackPathNode } from '@/types/attack-path'

// Minimal Finding factory — only the fields buildCandidateForFinding reads
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-aws-0035',
    category: 'NETWORK',
    resource_name: 'sg-0abc123',
    resource_id: 'sg-0abc123',
    ...overrides,
  } as Finding
}

function makeRemediation(overrides: Partial<RemediationRecord> = {}): RemediationRecord {
  return {
    id: 'rem-037',
    finding_id: 'f-azure-0002',
    domain: 'network',
    handler: 'iam-policy-scoper',
    tier: 2,
    status: 'pending',
    created_at: '2026-05-20T15:00:00Z',
    updated_at: '2026-05-20T15:00:00Z',
    result: {
      finding_id: 'f-azure-0002',
      success: false,
      message: 'pending',
      resource_id: 'arn:aws:iam::123:role/example',
      actions: [],
      started_at: '',
      completed_at: '',
      duration: '',
    },
    ...overrides,
  }
}

function makeAttackPathNode(overrides: Partial<AttackPathNode> = {}): AttackPathNode {
  return {
    id: 'node-1',
    finding_id: 'f-aws-0099',
    resource_id: 'sg-public-bastion',
    resource_name: 'admin-bastion-sg',
    resource_type: 'security_group',
    provider: 'aws',
    account_id: '123456789012',
    region: 'us-east-1',
    severity: 'HIGH',
    category: 'NETWORK',
    label: 'Bastion SG',
    ...overrides,
  }
}

function makeAttackPath(): AttackPath {
  return {
    id: 'ap-001',
    title: 'Public bastion to admin role',
    description: 'Network exposure chain',
    severity: 'HIGH',
    score: 78,
    hop_count: 3,
    entry_point: makeAttackPathNode(),
    target: makeAttackPathNode({ id: 'node-3' }),
    nodes: [],
    edges: [],
    mitre_tactics: [],
    finding_ids: [],
    ai_enriched: false,
  }
}

const noop = () => undefined

describe('RemediationActionDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('preview mode', () => {
    const context: DrawerContext = {
      mode: 'preview',
      finding: makeFinding(),
      candidate: buildCandidateForFinding(makeFinding()),
    }

    it('renders the preview title and key sections', () => {
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByText('Stage remediation')).toBeInTheDocument()
      expect(screen.getByText('Required permissions')).toBeInTheDocument()
      expect(screen.getByText('Planned actions')).toBeInTheDocument()
      // RollbackCard heading is "Rollback plan", optionally with window suffix
      expect(screen.getByText(/Rollback plan/)).toBeInTheDocument()
    })

    it('shows Cancel / Dry-run / Stage & execute footer for non-manual handler', () => {
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByRole('button', { name: /^Cancel$/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^Dry-run$/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Stage & execute/ })).toBeInTheDocument()
    })

    it('shows Open ticket CTA when candidate falls back to manual-escalation', () => {
      const threatFinding = makeFinding({ category: 'THREAT' })
      const threatContext: DrawerContext = {
        mode: 'preview',
        finding: threatFinding,
        candidate: buildCandidateForFinding(threatFinding),
      }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={threatContext} />)
      expect(screen.getByRole('button', { name: /Open ticket/ })).toBeInTheDocument()
    })

    it('fires onOpenChange(false) when Cancel is clicked', () => {
      const onOpenChange = vi.fn()
      renderWithProviders(<RemediationActionDrawer open onOpenChange={onOpenChange} context={context} />)
      fireEvent.click(screen.getByRole('button', { name: /^Cancel$/ }))
      expect(onOpenChange).toHaveBeenCalledWith(false)
    })
  })

  describe('approve mode', () => {
    it('shows Reject and Approve & execute for non-tier-3 handler', () => {
      const rec = makeRemediation()
      const context: DrawerContext = {
        mode: 'approve',
        remediation: rec,
        candidate: buildCandidateForRemediation(rec),
      }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByText('Approve staged remediation')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^Reject$/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Approve & execute/ })).toBeInTheDocument()
    })

    it('shows Open ticket link when tier-3 manual-escalation has an Asana URL', () => {
      const rec = makeRemediation({
        tier: 3,
        handler: 'manual-escalation',
        asana_task_url: 'https://app.asana.com/0/proj/task/1006',
      })
      const context: DrawerContext = {
        mode: 'approve',
        remediation: rec,
        candidate: buildCandidateForRemediation(rec),
      }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      const ticketLink = screen.getByRole('link', { name: /Open ticket/ })
      expect(ticketLink).toHaveAttribute('href', 'https://app.asana.com/0/proj/task/1006')
    })
  })

  describe('hop mode', () => {
    it('renders candidate picker when multiple candidates exist', () => {
      const node = makeAttackPathNode({ category: 'NETWORK' })
      const path = makeAttackPath()
      const candidates = buildCandidatesForNode(node, path)
      expect(candidates.length).toBeGreaterThan(1)
      const context: DrawerContext = { mode: 'hop', node, path, candidates }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByText(/Available remediations for this hop/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Stage selected/ })).toBeInTheDocument()
    })

    it('switches active candidate when picker option is clicked', () => {
      const node = makeAttackPathNode({ category: 'MISCONFIGURATION' })
      const path = makeAttackPath()
      const candidates = buildCandidatesForNode(node, path)
      // MISCONFIGURATION maps to multiple handlers — pick distinct labels
      expect(candidates.length).toBeGreaterThan(1)
      const context: DrawerContext = { mode: 'hop', node, path, candidates }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      // First candidate label is shown twice (picker + overview) by default
      const firstLabel = candidates[0].label
      const secondLabel = candidates[1].label
      // Click the second candidate in the picker
      fireEvent.click(screen.getAllByText(secondLabel)[0])
      // The CandidateOverview should now show the second candidate's label
      expect(screen.getAllByText(secondLabel).length).toBeGreaterThanOrEqual(2)
      // First label should now only appear in the picker, not the overview
      expect(screen.getAllByText(firstLabel).length).toBeLessThanOrEqual(1)
    })
  })

  describe('reversibility badge', () => {
    it('shows "reversible" for a reversible candidate', () => {
      const context: DrawerContext = {
        mode: 'preview',
        finding: makeFinding(),
        candidate: buildCandidateForFinding(makeFinding()),
      }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByText(/^reversible$/)).toBeInTheDocument()
    })

    it('shows "no SDK rollback" for manual-escalation', () => {
      const threatFinding = makeFinding({ category: 'THREAT' })
      const context: DrawerContext = {
        mode: 'preview',
        finding: threatFinding,
        candidate: buildCandidateForFinding(threatFinding),
      }
      renderWithProviders(<RemediationActionDrawer open onOpenChange={noop} context={context} />)
      expect(screen.getByText(/no SDK rollback/)).toBeInTheDocument()
    })
  })
})
