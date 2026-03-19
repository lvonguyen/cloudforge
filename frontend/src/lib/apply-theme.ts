/**
 * Theme preset system for whitelabel support.
 *
 * Each preset defines CSS custom property overrides for both light and dark modes.
 * The "sage" preset is the CloudForge identity (earthy green/tan/gold) — the values
 * in index.css @theme block. When sage is active, no overrides are applied (identity).
 *
 * Usage:
 *   applyTheme('neutral')                    // switch to gray/blue preset
 *   applyTheme('sage')                       // back to default (clears overrides)
 *   applyTheme(undefined, { primary: '#1e40af' })  // custom brand color on current preset
 */
import { branding } from '@/lib/branding'

interface ThemePalette {
  light: Record<string, string>
  dark: Record<string, string>
}

/**
 * Sage — the original CloudForge palette.
 * Earthy greens, warm tans, gold accent. These are the index.css defaults,
 * so applying this preset is a no-op (clears any runtime overrides).
 */
const SAGE: ThemePalette = { light: {}, dark: {} }

/**
 * Neutral — clean gray/slate with blue accent.
 * Generic enough for any enterprise deployment.
 */
const NEUTRAL: ThemePalette = {
  light: {
    '--color-background': '#F4F4F5',
    '--color-foreground': '#18181B',
    '--color-card': '#FFFFFF',
    '--color-card-foreground': '#18181B',
    '--color-popover': '#FFFFFF',
    '--color-popover-foreground': '#18181B',
    '--color-primary': '#18181B',
    '--color-primary-foreground': '#FAFAFA',
    '--color-secondary': '#F4F4F5',
    '--color-secondary-foreground': '#18181B',
    '--color-muted': '#F4F4F5',
    '--color-muted-foreground': '#71717A',
    '--color-accent': '#3B82F6',
    '--color-accent-foreground': '#FFFFFF',
    '--color-border': '#E4E4E7',
    '--color-input': '#E4E4E7',
    '--color-ring': '#3B82F6',
    '--color-sidebar-background': '#FAFAFA',
    '--color-sidebar-foreground': '#18181B',
    '--color-sidebar-primary': '#18181B',
    '--color-sidebar-primary-foreground': '#FAFAFA',
    '--color-sidebar-accent': '#F4F4F5',
    '--color-sidebar-accent-foreground': '#18181B',
    '--color-sidebar-border': '#E4E4E7',
    '--color-sidebar-ring': '#3B82F6',
  },
  dark: {
    '--color-background': '#09090B',
    '--color-foreground': '#FAFAFA',
    '--color-card': '#18181B',
    '--color-card-foreground': '#FAFAFA',
    '--color-popover': '#18181B',
    '--color-popover-foreground': '#FAFAFA',
    '--color-primary': '#FAFAFA',
    '--color-primary-foreground': '#09090B',
    '--color-secondary': '#27272A',
    '--color-secondary-foreground': '#FAFAFA',
    '--color-muted': '#27272A',
    '--color-muted-foreground': '#A1A1AA',
    '--color-accent': '#3B82F6',
    '--color-accent-foreground': '#FFFFFF',
    '--color-border': '#27272A',
    '--color-input': '#27272A',
    '--color-ring': '#3B82F6',
    '--color-sidebar-background': '#18181B',
    '--color-sidebar-foreground': '#FAFAFA',
    '--color-sidebar-primary': '#FAFAFA',
    '--color-sidebar-primary-foreground': '#09090B',
    '--color-sidebar-accent': '#27272A',
    '--color-sidebar-accent-foreground': '#FAFAFA',
    '--color-sidebar-border': '#27272A',
    '--color-sidebar-ring': '#3B82F6',
  },
}

/**
 * Corporate — dark navy with white/gold accents.
 * Enterprise/financial sector positioning.
 */
const CORPORATE: ThemePalette = {
  light: {
    '--color-background': '#F8FAFC',
    '--color-foreground': '#0F172A',
    '--color-card': '#FFFFFF',
    '--color-card-foreground': '#0F172A',
    '--color-popover': '#FFFFFF',
    '--color-popover-foreground': '#0F172A',
    '--color-primary': '#1E293B',
    '--color-primary-foreground': '#F8FAFC',
    '--color-secondary': '#F1F5F9',
    '--color-secondary-foreground': '#0F172A',
    '--color-muted': '#F1F5F9',
    '--color-muted-foreground': '#64748B',
    '--color-accent': '#D97706',
    '--color-accent-foreground': '#FFFFFF',
    '--color-border': '#E2E8F0',
    '--color-input': '#E2E8F0',
    '--color-ring': '#D97706',
    '--color-sidebar-background': '#1E293B',
    '--color-sidebar-foreground': '#F8FAFC',
    '--color-sidebar-primary': '#F8FAFC',
    '--color-sidebar-primary-foreground': '#1E293B',
    '--color-sidebar-accent': '#334155',
    '--color-sidebar-accent-foreground': '#F8FAFC',
    '--color-sidebar-border': '#334155',
    '--color-sidebar-ring': '#D97706',
  },
  dark: {
    '--color-background': '#020617',
    '--color-foreground': '#F8FAFC',
    '--color-card': '#0F172A',
    '--color-card-foreground': '#F8FAFC',
    '--color-popover': '#0F172A',
    '--color-popover-foreground': '#F8FAFC',
    '--color-primary': '#F8FAFC',
    '--color-primary-foreground': '#020617',
    '--color-secondary': '#1E293B',
    '--color-secondary-foreground': '#F8FAFC',
    '--color-muted': '#1E293B',
    '--color-muted-foreground': '#94A3B8',
    '--color-accent': '#D97706',
    '--color-accent-foreground': '#FFFFFF',
    '--color-border': '#1E293B',
    '--color-input': '#1E293B',
    '--color-ring': '#D97706',
    '--color-sidebar-background': '#0F172A',
    '--color-sidebar-foreground': '#F8FAFC',
    '--color-sidebar-primary': '#F8FAFC',
    '--color-sidebar-primary-foreground': '#0F172A',
    '--color-sidebar-accent': '#1E293B',
    '--color-sidebar-accent-foreground': '#F8FAFC',
    '--color-sidebar-border': '#1E293B',
    '--color-sidebar-ring': '#D97706',
  },
}

export const THEME_PRESETS: Record<string, ThemePalette> = {
  sage: SAGE,
  neutral: NEUTRAL,
  corporate: CORPORATE,
}

/**
 * Applies a theme preset and optional brand color overrides to the document.
 *
 * @param preset - Preset name ("sage", "neutral", "corporate"). Defaults to "sage".
 * @param overrides - Optional { primary, secondary, accent } hex values from branding.themeColors.
 */
export function applyTheme(
  preset?: string,
  overrides?: { primary?: string; secondary?: string; accent?: string },
): void {
  const root = document.documentElement
  const palette = THEME_PRESETS[preset ?? 'sage'] ?? SAGE
  const isDark = root.classList.contains('dark')
  const vars = isDark ? palette.dark : palette.light

  // Clear previous runtime overrides
  for (const key of Object.keys(NEUTRAL.light)) {
    root.style.removeProperty(key)
  }

  // Apply preset overrides (sage = no-op since values are empty)
  for (const [key, value] of Object.entries(vars)) {
    root.style.setProperty(key, value)
  }

  // Apply brand color overrides on top (from branding.themeColors or runtime config)
  if (overrides?.primary) {
    root.style.setProperty('--color-primary', overrides.primary)
    root.style.setProperty('--color-sidebar-primary', overrides.primary)
  }
  if (overrides?.secondary) {
    root.style.setProperty('--color-secondary', overrides.secondary)
    root.style.setProperty('--color-card', overrides.secondary)
  }
  if (overrides?.accent) {
    root.style.setProperty('--color-accent', overrides.accent)
    root.style.setProperty('--color-ring', overrides.accent)
    root.style.setProperty('--color-sidebar-ring', overrides.accent)
  }
}

/**
 * Initializes theme from branding config.
 * Called once from ConfigProvider after runtime config loads.
 */
export function initTheme(runtimeTheme?: string): void {
  const preset = runtimeTheme
    ?? (import.meta.env.VITE_THEME as string | undefined)
    ?? 'sage'

  const overrides = branding.themeColors
  const hasOverrides = overrides.primary || overrides.secondary || overrides.accent

  applyTheme(preset, hasOverrides ? overrides : undefined)
}
