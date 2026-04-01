import { test, expect } from '@playwright/test'

test.describe('Command Center page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops')
    // Wait for the page to finish loading
    await page.waitForLoadState('networkidle')
  })

  test('data layers panel is visible', async ({ page }) => {
    await expect(page.getByLabel('Data layer filters')).toBeVisible()
  })

  test('severity counts are displayed', async ({ page }) => {
    // The page should show severity labels somewhere (DataLayersPanel or summary charts)
    const hasCritical = await page.getByText('CRITICAL', { exact: true }).first().isVisible().catch(() => false)
    const hasHigh = await page.getByText('HIGH', { exact: true }).first().isVisible().catch(() => false)

    // At least one severity level should be shown
    expect(hasCritical || hasHigh).toBeTruthy()
  })

  test('charts or visualization is present', async ({ page }) => {
    // The CommandCenter renders charts, a prioritized queue, and graph views.
    const hasSvg = await page.locator('main svg').first().isVisible().catch(() => false)
    const hasCanvas = await page.locator('main canvas').first().isVisible().catch(() => false)
    const hasChart = await page.locator('.recharts-wrapper').first().isVisible().catch(() => false)
    const hasQueue = await page.getByText('Investigation Queue').first().isVisible().catch(() => false)
    const hasGraph = await page.locator('.react-flow').first().isVisible().catch(() => false)

    expect(hasSvg || hasCanvas || hasChart || hasQueue || hasGraph).toBeTruthy()
  })
})
