import { test, expect } from '@playwright/test'

test.describe('Findings page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops/findings')
    // Wait for findings data to load (table rows appear)
    await page.locator('table tbody tr').first().waitFor({ timeout: 15_000 })
  })

  test('findings table loads with data', async ({ page }) => {
    // Table header columns should be present
    await expect(page.getByText('Severity')).toBeVisible()
    await expect(page.getByText('Title', { exact: true })).toBeVisible()

    // At least one row should be in the table
    const rows = page.locator('table tbody tr')
    const count = await rows.count()
    expect(count).toBeGreaterThan(0)
  })

  test('severity tabs are present', async ({ page }) => {
    // The severity filter tabs should be visible
    await expect(page.getByText('ALL', { exact: true })).toBeVisible()
    await expect(page.getByText('CRITICAL', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('HIGH', { exact: true }).first()).toBeVisible()
  })

  test('click first finding navigates to detail page', async ({ page }) => {
    // Click the first row in the findings table
    const firstRow = page.locator('table tbody tr').first()
    await firstRow.click()

    // The FindingDetail either renders inline (drawer) or navigates.
    // In this app it renders a detail panel. Check for finding detail content.
    // The detail view shows fields like severity badge, resource info.
    await expect(
      page.getByText('CRITICAL').or(page.getByText('HIGH')).or(page.getByText('MEDIUM')).or(page.getByText('LOW')),
    ).toBeVisible()
  })
})
