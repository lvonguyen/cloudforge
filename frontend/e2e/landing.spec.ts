import { test, expect } from '@playwright/test'

test.describe('Landing page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('renders module cards', async ({ page }) => {
    // The landing page renders a "Modules" heading and project tiles
    await expect(page.getByRole('heading', { name: 'Modules' })).toBeVisible()

    // Module cards rendered as links inside the Modules section
    const cards = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Modules' }) }).locator('a[href]')
    const count = await cards.count()
    expect(count).toBeGreaterThanOrEqual(3)

    // Verify key module names are present
    await expect(page.getByText('CSPM Aggregator').first()).toBeVisible()
    await expect(page.getByText('Threat Intelligence').first()).toBeVisible()
    await expect(page.getByText('Remediation Engine').first()).toBeVisible()
    await expect(page.getByText('Operations Center').first()).toBeVisible()
  })

  test('renders architecture summary cards', async ({ page }) => {
    // 4 summary cards in the grid: Multi-Cloud, Policy Engine, Language, AI Providers
    // Use .first() to avoid strict mode violations (text also appears in module card tags)
    await expect(page.getByText('Multi-Cloud').first()).toBeVisible()
    await expect(page.getByText('Policy Engine').first()).toBeVisible()
    await expect(page.getByText('Language').first()).toBeVisible()
    await expect(page.getByText('AI Providers').first()).toBeVisible()

    // Verify values
    await expect(page.getByText('AWS / Azure / GCP').first()).toBeVisible()
    await expect(page.getByText('Dual OPA (REST + Embedded)')).toBeVisible()
  })

  test('renders demo access section when enabled', async ({ page }) => {
    // Demo access is behind VITE_DEMO_ACCESS_ENABLED flag
    const hasDemoSection = await page.getByText('Demo Access').isVisible().catch(() => false)
    test.skip(!hasDemoSection, 'Demo access not enabled in this environment')

    await expect(page.getByText('Demo Viewer')).toBeVisible()
    await expect(page.getByRole('button', { name: /Sign in as Demo Viewer/i })).toBeVisible()
  })
})
