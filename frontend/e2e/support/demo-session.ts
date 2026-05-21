import type { Page } from '@playwright/test'

export async function seedDemoRole(page: Page, role: 'admin' | 'operator' | 'requester' | 'viewer' = 'operator') {
  await page.addInitScript((selectedRole) => {
    sessionStorage.setItem('aegis_demo_session', 'true')
    sessionStorage.setItem('aegis_preview_role', selectedRole)
  }, role)
}
