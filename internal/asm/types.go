// Package asm provides attack surface management (ASM) scanning types and interfaces.
package asm

import "time"

// ServiceProtocol identifies the protocol of an exposed service.
type ServiceProtocol string

const (
	ProtocolHTTP  ServiceProtocol = "http"
	ProtocolHTTPS ServiceProtocol = "https"
	ProtocolSSH   ServiceProtocol = "ssh"
	ProtocolDNS   ServiceProtocol = "dns"
	ProtocolSMTP  ServiceProtocol = "smtp"
	ProtocolFTP   ServiceProtocol = "ftp"
	ProtocolOther ServiceProtocol = "other"
)

// ScanRequest is the input for an ASM scan.
type ScanRequest struct {
	Domain string `json:"domain"`
}

// ScanResult is the output of an ASM scan.
type ScanResult struct {
	Domain    string    `json:"domain"`
	Assets    []Asset   `json:"assets"`
	ScannedAt time.Time `json:"scanned_at"`
}

// Asset represents a discovered external-facing resource.
type Asset struct {
	ID        string           `json:"id"`
	Hostname  string           `json:"hostname"`
	IP        string           `json:"ip"`
	Services  []ExposedService `json:"services"`
	Certs     []Certificate    `json:"certs,omitempty"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
}

// ExposedService represents a network service listening on a port.
type ExposedService struct {
	Port     int             `json:"port"`
	Protocol ServiceProtocol `json:"protocol"`
	Banner   string          `json:"banner,omitempty"`
	TLS      bool            `json:"tls"`
}

// Certificate represents a TLS certificate found on an asset.
type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SANs      []string  `json:"sans,omitempty"`
}
