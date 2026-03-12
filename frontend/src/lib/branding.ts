/**
 * Centralized branding configuration.
 * All tenant-specific strings are read from Vite env vars with sensible defaults.
 * Override via .env.development or per-tenant .env files (e.g. .env.haea).
 */
export const branding = {
  /** Display name of the deploying organization (e.g. "Contoso", "HAEA"). */
  companyName: import.meta.env.VITE_COMPANY_NAME || 'Contoso',

  /** Product name shown in nav, headings, and title bar. */
  productName: import.meta.env.VITE_PRODUCT_NAME || 'CloudForge',

  /** Path to the primary logo SVG (relative to /public). */
  logoPath: import.meta.env.VITE_LOGO_PATH || '/icons/cloudforge-logo.svg',

  /** Email domain used for default/demo user emails. */
  emailDomain: import.meta.env.VITE_EMAIL_DOMAIN || 'contoso.dev',

  /** GitHub org/user prefix for repo links on landing page. */
  repoPrefix: import.meta.env.VITE_REPO_PREFIX || 'github.com/contoso',
} as const
