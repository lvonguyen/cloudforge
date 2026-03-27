import { test, expect } from '@playwright/test'

test.describe('Role switcher', () => {
  /** Open the role dropdown in the top nav and select a role by label. */
  async function switchToRole(page: import('@playwright/test').Page, dropdownLabel: string) {
    // The RoleSwitcher trigger shows current role text + chevron
    const trigger = page.locator('button').filter({ hasText: /Admin|Operator|Requester|Demo Viewer/ }).first()
    await trigger.click()

    // Wait for dropdown content
    await page.getByText('Switch Role').waitFor()
    await page.getByText(dropdownLabel).click()
  }

  test('switch to Admin — redirects to /admin', async ({ page }) => {
    await page.goto('/')
    await switchToRole(page, 'Admin — Platform & Users')
    await expect(page).toHaveURL(/\/admin/)

    // Admin sidebar should show admin nav items
    await expect(page.getByText('Dashboard')).toBeVisible()
    await expect(page.getByText('Policies')).toBeVisible()
  })

  test('switch to Operator — redirects to /ops', async ({ page }) => {
    await page.goto('/')
    await switchToRole(page, 'Operator — SecOps & Intel')
    await expect(page).toHaveURL(/\/ops/)

    // Operator sidebar should show ops nav items
    await expect(page.getByText('Command Center')).toBeVisible()
    await expect(page.getByText('Findings')).toBeVisible()
  })

  test('switch to Requester — redirects to /portal', async ({ page }) => {
    await page.goto('/')
    await switchToRole(page, 'Requester — Self-Service')
    await expect(page).toHaveURL(/\/portal/)

    // Requester sidebar should show portal nav items
    await expect(page.getByText('My Dashboard')).toBeVisible()
    await expect(page.getByText('New Request')).toBeVisible()
  })

  test('switch to Viewer — redirects to /ops/findings', async ({ page }) => {
    await page.goto('/')
    await switchToRole(page, 'Demo Viewer — All Modules')
    await expect(page).toHaveURL(/\/ops\/findings/)
  })
})
