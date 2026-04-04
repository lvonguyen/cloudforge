import { test, expect } from '@playwright/test'

test.describe('Compliance page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops/compliance')
    await expect(page.getByRole('heading', { name: 'Compliance Status' })).toBeVisible()
  })

  test('framework summary renders', async ({ page }) => {
    await expect(page.getByText(/frameworks tracked/i)).toBeVisible()
    await expect(page.getByText('Average Score')).toBeVisible()
    await expect(page.getByText('Framework Health')).toBeVisible()
  })

  test('framework detail list is visible', async ({ page }) => {
    const hasFramework =
      await page.getByText('NIST CSF 2.0').first().isVisible().catch(() => false) ||
      await page.getByText('PCI-DSS v4.0').first().isVisible().catch(() => false) ||
      await page.getByText('HIPAA').first().isVisible().catch(() => false)

    expect(hasFramework).toBeTruthy()
  })
})
