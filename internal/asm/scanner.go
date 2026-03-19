package asm

import "context"

// ASMScanner discovers external-facing assets for a domain.
type ASMScanner interface {
	ScanDomain(ctx context.Context, domain string) (*ScanResult, error)
}
