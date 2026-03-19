// Package aegispath provides a CGo bridge to the Rust libaegispath library
// for high-performance attack path computation and data loading.
//
// Build the Rust library first:
//
//	cd rust/libaegispath && cargo build --release
//
// Then run Go with CGo enabled:
//
//	CGO_ENABLED=1 go test ./rust/... -v
package aegispath

/*
#cgo darwin LDFLAGS: -L${SRCDIR}/libaegispath/target/release -laegispath
#cgo linux LDFLAGS: -L${SRCDIR}/libaegispath/target/release -laegispath -lm -ldl -lpthread
#include <stdint.h>
#include <stddef.h>

// aegis_compute_attack_paths takes a JSON []Finding, returns JSON AttackPathResult.
// Caller must free the returned buffer with aegis_free.
extern uint8_t* aegis_compute_attack_paths(const uint8_t* json_ptr, size_t json_len, size_t* out_len);

// aegis_load_and_serialize_findings loads findings JSON, applies a filter, and serializes.
// filter_ptr may be NULL (no filter). Caller must free the result with aegis_free.
extern uint8_t* aegis_load_and_serialize_findings(
    const uint8_t* json_ptr, size_t json_len,
    const uint8_t* filter_ptr, size_t filter_len,
    size_t* out_len);

extern void aegis_free(uint8_t* ptr, size_t len);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// copyAndFree copies a Rust-owned buffer into Go memory, then frees the Rust side.
// Uses unsafe.Slice to avoid C.int truncation on buffers >2GB.
func copyAndFree(ptr *C.uint8_t, length C.size_t) []byte {
	n := int(length)
	goSlice := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n)
	result := make([]byte, n)
	copy(result, goSlice)
	C.aegis_free(ptr, length)
	return result
}

// ComputeAttackPaths calls the Rust BFS implementation via FFI.
// Input: JSON-encoded []Finding. Output: JSON-encoded AttackPathResult.
func ComputeAttackPaths(findingsJSON []byte) ([]byte, error) {
	if len(findingsJSON) == 0 {
		return nil, fmt.Errorf("empty findings JSON")
	}

	var outLen C.size_t
	resultPtr := C.aegis_compute_attack_paths(
		(*C.uint8_t)(unsafe.Pointer(&findingsJSON[0])),
		C.size_t(len(findingsJSON)),
		&outLen,
	)
	if resultPtr == nil {
		return nil, fmt.Errorf("aegis_compute_attack_paths returned null: input_len=%d", len(findingsJSON))
	}

	return copyAndFree(resultPtr, outLen), nil
}

// LoadAndSerializeFindings deserializes findings JSON, applies an optional
// filter, and re-serializes the result — all in Rust (serde) for speed.
// filterJSON may be nil for unfiltered output.
func LoadAndSerializeFindings(findingsJSON, filterJSON []byte) ([]byte, error) {
	if len(findingsJSON) == 0 {
		return nil, fmt.Errorf("empty findings JSON")
	}

	var filterPtr *C.uint8_t
	var filterLen C.size_t
	if len(filterJSON) > 0 {
		filterPtr = (*C.uint8_t)(unsafe.Pointer(&filterJSON[0]))
		filterLen = C.size_t(len(filterJSON))
	}

	var outLen C.size_t
	resultPtr := C.aegis_load_and_serialize_findings(
		(*C.uint8_t)(unsafe.Pointer(&findingsJSON[0])),
		C.size_t(len(findingsJSON)),
		filterPtr,
		filterLen,
		&outLen,
	)
	if resultPtr == nil {
		return nil, fmt.Errorf("aegis_load_and_serialize_findings returned null: input_len=%d", len(findingsJSON))
	}

	return copyAndFree(resultPtr, outLen), nil
}
