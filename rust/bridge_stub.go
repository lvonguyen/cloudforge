//go:build !(cgo && rust)

// Stub implementations when Rust library is not available.
// Active when: no rust tag, or rust tag without CGo (cross-compilation).
// Build with CGO_ENABLED=1 -tags rust to use the real CGo bridge.
package aegispath

import "errors"

var errNoRust = errors.New("aegispath: Rust FFI not available (build with CGO_ENABLED=1 -tags rust)")

func ComputeAttackPaths(_ []byte) ([]byte, error) {
	return nil, errNoRust
}

func LoadAndSerializeFindings(_, _ []byte) ([]byte, error) {
	return nil, errNoRust
}
