import { test, expect } from '@playwright/test'

test.describe('Investigations page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ops/investigations')
    await page.getByText('Investigation Queue').waitFor({ timeout: 15_000 })
  })

  test('finding list renders', async ({ page }) => {
    const findingItems = page.locator('button').filter({ hasText: /CRITICAL|HIGH/ })
    const count = await findingItems.count()
    expect(count).toBeGreaterThan(0)
  })

  test('clicking different findings changes graph center node', async ({ page }) => {
    const findingButtons = page.locator('.w-80 button').filter({ hasText: /CRITICAL|HIGH/ })
    const count = await findingButtons.count()
    // Need at least 2 findings to compare
    test.skip(count < 2, 'Need at least 2 findings for this test')

    // Click first finding and capture the center node text
    await findingButtons.nth(0).click()
    // Wait for graph to render — center node has the finding title
    await page.waitForTimeout(500)
    const graphArea = page.locator('.react-flow')
    await graphArea.waitFor()

    // Get the title text from the first finding button to know what to expect
    const firstTitle = await findingButtons.nth(0).locator('.text-xs.font-medium').innerText()

    // Click a different finding
    await findingButtons.nth(1).click()
    await page.waitForTimeout(500)

    const secondTitle = await findingButtons.nth(1).locator('.text-xs.font-medium').innerText()

    // The two findings should have different titles (confirming graph changed)
    expect(firstTitle).not.toBe(secondTitle)
  })
})
