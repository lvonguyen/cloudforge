/**
 * Mock data transformation utilities for whitelabel support.
 *
 * Instead of modifying 100+ hardcoded email addresses in JSON files,
 * we apply a runtime transform that replaces the default "contoso.dev"
 * domain with the tenant's configured emailDomain from branding.ts.
 *
 * This approach:
 * - Keeps mock JSON files pristine (easy to diff / regenerate)
 * - Works for any JSON shape without per-field knowledge
 * - Is only applied to mock data paths (zero production cost)
 */
import { branding } from '@/lib/branding'

const DEFAULT_EMAIL_DOMAIN = 'contoso.dev'

/**
 * Recursively replaces the default email domain with the tenant's
 * configured domain in any JSON-serializable value.
 *
 * Handles strings, arrays, and nested objects.
 */
export function brandMockData<T>(data: T): T {
  if (branding.emailDomain === DEFAULT_EMAIL_DOMAIN) {
    return data // no-op when using default branding
  }
  return replaceEmailDomain(data, DEFAULT_EMAIL_DOMAIN, branding.emailDomain)
}

function replaceEmailDomain<T>(value: T, from: string, to: string): T {
  if (typeof value === 'string') {
    return value.replaceAll(from, to) as T
  }
  if (Array.isArray(value)) {
    return value.map(item => replaceEmailDomain(item, from, to)) as T
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      result[k] = replaceEmailDomain(v, from, to)
    }
    return result as T
  }
  return value
}

/**
 * Replaces the default registry domain in Rego policy snippets and
 * other infrastructure references.
 *
 * Default: "ecr.contoso.dev", "acr.contoso.dev", "gcr.contoso.dev"
 * Replaced with the tenant's emailDomain-based registry references.
 */
export function brandRegistryRefs(text: string): string {
  if (branding.emailDomain === DEFAULT_EMAIL_DOMAIN) {
    return text
  }
  return text
    .replaceAll(`ecr.${DEFAULT_EMAIL_DOMAIN}`, `ecr.${branding.emailDomain}`)
    .replaceAll(`acr.${DEFAULT_EMAIL_DOMAIN}`, `acr.${branding.emailDomain}`)
    .replaceAll(`gcr.${DEFAULT_EMAIL_DOMAIN}`, `gcr.${branding.emailDomain}`)
}

/**
 * Creates a branded email address using the tenant's email domain.
 * Use this for generating new mock emails in component code.
 *
 * @example brandEmail('operator1') => 'operator1@acme.example.com'
 */
export function brandEmail(localPart: string): string {
  return `${localPart}@${branding.emailDomain}`
}
