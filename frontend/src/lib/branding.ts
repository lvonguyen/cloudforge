import type { RuntimeConfig } from '@/lib/runtime-config'

export interface Branding {
  companyName: string
  productName: string
  logoPath: string
  emailDomain: string
  repoPrefix: string
  enabledModules: string[]
  storagePrefix: string
  themeColors: {
    primary: string
    secondary: string
    accent: string
  }
  demoAccess: {
    enabled: boolean
    email: string
    password: string
  }
}

/**
 * Centralized branding configuration.
 * All tenant-specific strings are read from Vite env vars with sensible defaults.
 * Runtime config may override the visible branding after boot.
 */
export const branding: Branding = {
  companyName: import.meta.env.VITE_COMPANY_NAME || 'Contoso',
  productName: import.meta.env.VITE_PRODUCT_NAME || 'Aegis',
  logoPath: import.meta.env.VITE_LOGO_PATH || '/icons/aegis-logo.svg',
  emailDomain: import.meta.env.VITE_EMAIL_DOMAIN || 'contoso.dev',
  repoPrefix: import.meta.env.VITE_REPO_PREFIX || 'github.com/contoso',
  enabledModules: (import.meta.env.VITE_ENABLED_MODULES || 'aegis,cspm-aggregator,threat-intel,remediation-engine,ops-center')
    .split(',')
    .map((s: string) => s.trim()),
  storagePrefix: import.meta.env.VITE_STORAGE_PREFIX || 'aegis',
  themeColors: {
    primary: import.meta.env.VITE_BRAND_PRIMARY || '',
    secondary: import.meta.env.VITE_BRAND_SECONDARY || '',
    accent: import.meta.env.VITE_BRAND_ACCENT || '',
  },
  demoAccess: {
    enabled: import.meta.env.VITE_DEMO_ACCESS_ENABLED === 'true',
    email: import.meta.env.VITE_DEMO_VIEWER_EMAIL || '',
    password: import.meta.env.VITE_DEMO_VIEWER_PASSWORD || '',
  },
}

export function applyRuntimeBranding(config: RuntimeConfig | null): void {
  if (!config) return

  if (config.companyName) branding.companyName = config.companyName
  if (config.productName) branding.productName = config.productName
  if (config.logoPath) branding.logoPath = config.logoPath
  if (config.emailDomain) branding.emailDomain = config.emailDomain
  if (config.repoPrefix) branding.repoPrefix = config.repoPrefix
  if (config.storagePrefix) branding.storagePrefix = config.storagePrefix
  if (Array.isArray(config.enabledModules) && config.enabledModules.length > 0) {
    branding.enabledModules = [...config.enabledModules]
  }
  if (config.theme) {
    branding.themeColors = {
      primary: config.theme.primaryColor || branding.themeColors.primary,
      secondary: config.theme.secondaryColor || branding.themeColors.secondary,
      accent: config.theme.accentColor || branding.themeColors.accent,
    }
  }
}
