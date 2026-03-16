import { branding } from '@/lib/branding'

export function Footer() {
  return (
    <footer className="border-t border-border bg-background px-6 py-3 text-xs text-muted-foreground flex items-center justify-between">
      <span>{branding.productName} v0.9 — {new Date().getFullYear()}</span>
      <span>{branding.companyName}</span>
    </footer>
  )
}
