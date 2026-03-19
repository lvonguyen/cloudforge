package asm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// MockScanner returns deterministic synthetic assets seeded by domain name.
type MockScanner struct{}

func NewMockScanner() ASMScanner {
	return &MockScanner{}
}

func (m *MockScanner) ScanDomain(_ context.Context, domain string) (*ScanResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	seed := domainSeed(domain)
	now := time.Now().UTC()

	assets := []Asset{
		{
			ID:       fmt.Sprintf("asset-%s-web", domain),
			Hostname: "www." + domain,
			IP:       syntheticIP(seed, 0),
			Services: []ExposedService{
				{Port: 443, Protocol: ProtocolHTTPS, TLS: true},
				{Port: 80, Protocol: ProtocolHTTP, TLS: false},
			},
			Certs: []Certificate{{
				Subject:   "www." + domain,
				Issuer:    "Let's Encrypt Authority X3",
				NotBefore: now.Add(-90 * 24 * time.Hour),
				NotAfter:  now.Add(time.Duration(seed%180) * 24 * time.Hour),
				SANs:      []string{"www." + domain, domain},
			}},
			FirstSeen: now.Add(-30 * 24 * time.Hour),
			LastSeen:  now,
		},
		{
			ID:       fmt.Sprintf("asset-%s-api", domain),
			Hostname: "api." + domain,
			IP:       syntheticIP(seed, 1),
			Services: []ExposedService{
				{Port: 443, Protocol: ProtocolHTTPS, TLS: true},
			},
			FirstSeen: now.Add(-20 * 24 * time.Hour),
			LastSeen:  now,
		},
		{
			ID:       fmt.Sprintf("asset-%s-ssh", domain),
			Hostname: "bastion." + domain,
			IP:       syntheticIP(seed, 2),
			Services: []ExposedService{
				{Port: 22, Protocol: ProtocolSSH, Banner: "OpenSSH_8.9", TLS: false},
			},
			FirstSeen: now.Add(-60 * 24 * time.Hour),
			LastSeen:  now,
		},
	}

	return &ScanResult{
		Domain:    domain,
		Assets:    assets,
		ScannedAt: now,
	}, nil
}

func domainSeed(domain string) uint64 {
	h := sha256.Sum256([]byte(domain))
	return binary.BigEndian.Uint64(h[:8])
}

func syntheticIP(seed uint64, offset int) string {
	s := seed + uint64(offset)*7919
	return fmt.Sprintf("10.%d.%d.%d", (s>>16)%256, (s>>8)%256, s%256)
}
