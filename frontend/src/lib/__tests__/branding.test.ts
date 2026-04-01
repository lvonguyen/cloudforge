import { afterEach, describe, expect, it } from 'vitest'
import { applyRuntimeBranding, branding } from '@/lib/branding'
import type { RuntimeConfig } from '@/lib/runtime-config'

const baseline = {
  companyName: branding.companyName,
  productName: branding.productName,
  logoPath: branding.logoPath,
  emailDomain: branding.emailDomain,
  repoPrefix: branding.repoPrefix,
  enabledModules: [...branding.enabledModules],
  storagePrefix: branding.storagePrefix,
  themeColors: { ...branding.themeColors },
}

function restoreBranding() {
  branding.companyName = baseline.companyName
  branding.productName = baseline.productName
  branding.logoPath = baseline.logoPath
  branding.emailDomain = baseline.emailDomain
  branding.repoPrefix = baseline.repoPrefix
  branding.enabledModules = [...baseline.enabledModules]
  branding.storagePrefix = baseline.storagePrefix
  branding.themeColors = { ...baseline.themeColors }
}

afterEach(() => {
  restoreBranding()
})

describe('applyRuntimeBranding', () => {
  it('overrides visible branding with runtime config values', () => {
    branding.productName = 'CloudForge Legacy'
    branding.logoPath = '/logo.svg'
    branding.enabledModules = ['legacy-module']
    branding.themeColors = { primary: '', secondary: '', accent: '' }

    const runtime: RuntimeConfig = {
      companyName: 'Contoso Inc.',
      productName: 'CloudForge',
      logoPath: '/icons/aegis-logo.svg',
      emailDomain: 'contoso.dev',
      repoPrefix: 'github.com/contoso',
      enabledModules: ['cloudforge', 'posture-management'],
      storagePrefix: 'aegis',
      theme: {
        primaryColor: '#111111',
        secondaryColor: '#222222',
        accentColor: '#333333',
      },
    }

    applyRuntimeBranding(runtime)

    expect(branding.productName).toBe('CloudForge')
    expect(branding.logoPath).toBe('/icons/aegis-logo.svg')
    expect(branding.enabledModules).toEqual(['cloudforge', 'posture-management'])
    expect(branding.themeColors).toEqual({
      primary: '#111111',
      secondary: '#222222',
      accent: '#333333',
    })
  })

  it('ignores null runtime config', () => {
    const before = branding.productName
    applyRuntimeBranding(null)
    expect(branding.productName).toBe(before)
  })
})
