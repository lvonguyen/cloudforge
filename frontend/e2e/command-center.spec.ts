import { test, expect } from '@playwright/test'

test.describe('Command Center page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops')
    // Wait for the page to finish loading
    await page.waitForLoadState('networkidle')
  })

  test('data layers panel is visible', async ({ page }) => {
    // The DataLayersPanel shows filter groups for findings
    // Check for severity-related filter text
    await expect(
      page.getByText('severity', { exact: false }).or(page.getByText('Severity')),
    ).toBeVisible()
  })

  test('severity counts are displayed', async ({ page }) => {
    // The page should show severity labels somewhere (DataLayersPanel or summary charts)
    const hasCritical = await page.getByText('CRITICAL', { exact: true }).first().isVisible().catch(() => false)
    const hasHigh = await page.getByText('HIGH', { exact: true }).first().isVisible().catch(() => false)

    // At least one severity level should be shown
    expect(hasCritical || hasHigh).toBeTruthy()
  })

  test('charts or treemap view is present', async ({ page }) => {
    // The CommandCenter renders FindingsSummaryChart and/or FindingsTreemap
    // Check for either chart containers or the treemap data-testid
    const hasTreemap = await page.locator('[data-testid="findings-treemap"]').isVisible().catch(() => false)
    const hasChart = await page.locator('.recharts-wrapper').isVisible().catch(() => false)
    const hasGraph = await page.locator('.react-flow').isVisible().catch(() => false)

    // At least one visualization should be present
    expect(hasTreemap || hasChart || hasGraph).toBeTruthy()
  })
})
