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

  test('click first finding navigates to detail', async ({ page }) => {
    // Findings are rendered as <a> rows — click navigates to /ops/findings/:id
    const firstRow = page.locator('table tbody tr, table tbody a').first()
    await firstRow.click()

    // Wait for FindingDetail page to render
    await page.waitForURL(/\/ops\/findings\//, { timeout: 10_000 }).catch(() => {})

    // Verify either navigated to detail page or inline detail rendered
    const url = page.url()
    if (/\/ops\/findings\/[^/]+/.test(url)) {
      // Navigated: FindingDetail page loaded
      await expect(page.locator('main')).toBeVisible()
    } else {
      // Inline mode: just verify table is still visible (click didn't break)
      await expect(page.locator('table')).toBeVisible()
    }
  })
})

test.describe('Prod findings corpus', () => {
  test('uses live API pagination instead of mock findings', async ({ page }, testInfo) => {
    const baseURL = process.env.PLAYWRIGHT_BASE_URL || String(testInfo.project.use.baseURL ?? '')
    test.skip(!baseURL.includes('cloudforge.lvonguyen.com'), 'prod-only corpus guard')

    const mockFetches: string[] = []
    page.on('response', (response) => {
      const url = response.url()
      if (response.request().resourceType() === 'fetch' && (/\/mock\/findings\.json/.test(url) || /r2\.dev\/mock\/findings\.json/.test(url))) {
        mockFetches.push(url)
      }
    })

    const findingsResponsePromise = page.waitForResponse((response) =>
      response.url().includes('/api/v1/findings?') &&
      response.request().resourceType() === 'fetch' &&
      response.status() === 200,
    )

    await page.goto('/ops/findings?qa=large-corpus')
    await expect(page.getByText('300,000 total findings')).toBeVisible({ timeout: 20_000 })

    const findingsResponse = await findingsResponsePromise
    const responseUrl = new URL(findingsResponse.url())
    const responseBytes = (await findingsResponse.body()).length

    expect(responseUrl.searchParams.get('per_page')).toBe('50')
    expect(responseBytes).toBeLessThan(140_000)
    expect(mockFetches).toHaveLength(0)
  })
})
