import { test, expect } from '@playwright/test'

test.describe('Landing page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
  })

  test('renders module cards', async ({ page }) => {
    // The landing page renders a "Modules" heading and project tiles
    await expect(page.getByText('Modules')).toBeVisible()

    // 5 module cards: Cloud Aegis, CSPM Aggregator, Threat Intelligence, Remediation Engine, Operations Center
    const cards = page.locator('section').filter({ hasText: 'Modules' }).locator('a[href]')
    await expect(cards).toHaveCount(5)

    // Verify key module names are present
    await expect(page.getByText('CSPM Aggregator')).toBeVisible()
    await expect(page.getByText('Threat Intelligence')).toBeVisible()
    await expect(page.getByText('Remediation Engine')).toBeVisible()
    await expect(page.getByText('Operations Center')).toBeVisible()
  })

  test('renders architecture summary cards', async ({ page }) => {
    // 4 summary cards in the grid: Multi-Cloud, Policy Engine, Language, AI Providers
    await expect(page.getByText('Multi-Cloud')).toBeVisible()
    await expect(page.getByText('Policy Engine')).toBeVisible()
    await expect(page.getByText('Language')).toBeVisible()
    await expect(page.getByText('AI Providers')).toBeVisible()

    // Verify values
    await expect(page.getByText('AWS / Azure / GCP')).toBeVisible()
    await expect(page.getByText('Dual OPA (REST + Embedded)')).toBeVisible()
  })

  test('renders demo access section', async ({ page }) => {
    await expect(page.getByText('Demo Access')).toBeVisible()
    await expect(page.getByText('Demo Viewer')).toBeVisible()
    await expect(page.getByRole('button', { name: /Sign in as Demo Viewer/i })).toBeVisible()
  })
})
