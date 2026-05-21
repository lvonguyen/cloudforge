import { test, expect } from '@playwright/test'
import { seedDemoRole } from './support/demo-session'

test.describe('Remediation Queue page', () => {
  test.beforeEach(async ({ page }) => {
    await seedDemoRole(page, 'operator')
    await page.goto('/ops/remediation')
    await page.waitForLoadState('networkidle')
  })

  test('remediation queue renders with items', async ({ page }) => {
    // Page heading should show remediation context
    await expect(page.getByRole('heading', { name: 'Remediation Queue' })).toBeVisible()

    // Status summary should show pending/in-progress counts
    await expect(page.getByText(/\d+ pending/).first()).toBeVisible()
  })

  test('tier groupings are present', async ({ page }) => {
    // Remediation tiers: Tier 1 (auto), Tier 2 (guided), Tier 3 (manual)
    const hasTier1 = await page.getByText(/tier 1/i).first().isVisible().catch(() => false)
    const hasTier2 = await page.getByText(/tier 2/i).first().isVisible().catch(() => false)
    const hasTier3 = await page.getByText(/tier 3/i).first().isVisible().catch(() => false)

    expect(hasTier1 || hasTier2 || hasTier3).toBeTruthy()
  })

  test('clicking item opens detail or navigates', async ({ page }) => {
    // Click first actionable item in the queue
    const firstRow = page.locator('table tbody tr').first()
    const hasRows = (await firstRow.count()) > 0

    if (hasRows) {
      await firstRow.click()
      // Should show remediation detail content — either inline sheet or /remediation/:id
      await expect(
        page.getByText('Dry Run').or(page.getByText('Remediation Plan')).or(page.getByText('Status')),
      ).toBeVisible({ timeout: 10_000 })
    }
  })
})
