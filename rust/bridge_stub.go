//go:build !rust

// Stub implementations when Rust library is not available.
// Build with -tags rust to use the real CGo bridge.
package aegispath

import "fmt"

var errNoRust = fmt.Errorf("aegispath: Rust FFI not available (build with -tags rust)")

func ComputeAttackPaths(_ []byte) ([]byte, error) {
	return nil, errNoRust
}

func LoadAndSerializeFindings(_, _ []byte) ([]byte, error) {
	return nil, errNoRust
}
