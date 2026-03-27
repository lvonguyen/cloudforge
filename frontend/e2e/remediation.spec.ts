import { test, expect } from '@playwright/test'

test.describe('Remediation Queue page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops/remediation')
    await page.waitForLoadState('networkidle')
  })

  test('remediation queue renders with items', async ({ page }) => {
    // Page heading or tab should indicate remediation context
    await expect(
      page.getByText('Remediation', { exact: false }).first(),
    ).toBeVisible()

    // Queue should show items — either table rows or cards
    const rows = page.locator('table tbody tr')
    const cards = page.locator('[data-testid="remediation-card"]')
    const rowCount = await rows.count().catch(() => 0)
    const cardCount = await cards.count().catch(() => 0)

    expect(rowCount + cardCount).toBeGreaterThan(0)
  })

  test('tier badges are present', async ({ page }) => {
    // Remediation items should show tier badges (AUTO, GUIDED, MANUAL)
    const hasAuto = await page.getByText('AUTO', { exact: true }).first().isVisible().catch(() => false)
    const hasGuided = await page.getByText('GUIDED', { exact: true }).first().isVisible().catch(() => false)
    const hasManual = await page.getByText('MANUAL', { exact: true }).first().isVisible().catch(() => false)

    expect(hasAuto || hasGuided || hasManual).toBeTruthy()
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
