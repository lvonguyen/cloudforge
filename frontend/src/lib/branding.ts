/**
 * Centralized branding configuration.
 * All tenant-specific strings are read from Vite env vars with sensible defaults.
 * Override via .env.development or per-tenant .env files (e.g. .env.haea).
 *
 * Phase 2: Added enabledModules, storagePrefix, and theme color vars.
 */
export const branding = {
  /** Display name of the deploying organization (e.g. "Contoso", "HAEA"). */
  companyName: import.meta.env.VITE_COMPANY_NAME || 'Contoso',

  /** Product name shown in nav, headings, and title bar. */
  productName: import.meta.env.VITE_PRODUCT_NAME || 'Cloud Aegis',

  /** Path to the primary logo SVG (relative to /public). */
  logoPath: import.meta.env.VITE_LOGO_PATH || '/icons/aegis-logo.svg',

  /** Email domain used for default/demo user emails. */
  emailDomain: import.meta.env.VITE_EMAIL_DOMAIN || 'contoso.dev',

  /** GitHub org/user prefix for repo links on landing page. */
  repoPrefix: import.meta.env.VITE_REPO_PREFIX || 'github.com/contoso',

  /**
   * Comma-separated list of enabled module slugs.
   * Controls which project cards appear on the landing page.
   * Default shows both core modules.
   */
  enabledModules: (import.meta.env.VITE_ENABLED_MODULES || 'aegis,cspm-aggregator')
    .split(',')
    .map((s: string) => s.trim()),

  /**
   * Prefix for localStorage/sessionStorage keys.
   * Prevents key collisions when multiple tenants share a browser in dev.
   */
  storagePrefix: import.meta.env.VITE_STORAGE_PREFIX || 'aegis',

  /**
   * Brand theme colors (CSS hex values).
   * Applied as CSS custom properties at :root for per-tenant visual identity.
   * See theme.ts for the full theming pipeline.
   */
  themeColors: {
    primary: import.meta.env.VITE_BRAND_PRIMARY || '',
    secondary: import.meta.env.VITE_BRAND_SECONDARY || '',
    accent: import.meta.env.VITE_BRAND_ACCENT || '',
  },

  /**
   * Demo viewer access configuration.
   * When enabled, the landing page shows a "Demo Viewer" card with
   * pre-filled credentials that initiate the real Okta SSO flow.
   */
  demoAccess: {
    enabled: import.meta.env.VITE_DEMO_ACCESS_ENABLED === 'true',
    email: import.meta.env.VITE_DEMO_VIEWER_EMAIL || '',
    password: import.meta.env.VITE_DEMO_VIEWER_PASSWORD || '',
  },
} as const

export type Branding = typeof branding
