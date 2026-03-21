pub mod attackpath;
pub mod loader;
pub mod types;

use std::slice;

/// Maximum input buffer size for FFI entry points (64MB).
/// Prevents a single call from OOM-ing the shared Go/Rust process.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum filter buffer size (64KB — filter JSON is tiny).
const MAX_FILTER_BYTES: usize = 64 * 1024;

/// Compute attack paths from a JSON array of findings.
///
/// # Safety
///
/// - `json_ptr` must point to a valid UTF-8 byte buffer of length `json_len`.
/// - `out_len` must point to a writable `usize`.
/// - The returned pointer must be freed with `aegis_free`.
/// - Returns null on error (parse failure, empty input).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_compute_attack_paths(
    json_ptr: *const u8,
    json_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if json_ptr.is_null() || out_len.is_null() || json_len == 0 || json_len > MAX_INPUT_BYTES {
        return std::ptr::null_mut();
    }

    let input = unsafe { slice::from_raw_parts(json_ptr, json_len) };

    let findings: Vec<types::Finding> = match serde_json::from_slice(input) {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = attackpath::compute_attack_paths(&findings);

    let output = match serde_json::to_vec(&result) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    // into_boxed_slice() guarantees capacity == length (unlike shrink_to_fit),
    // so aegis_free can safely reconstruct with Vec::from_raw_parts(ptr, len, len).
    let boxed = output.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;

    unsafe { *out_len = len };
    ptr
}

/// Load findings from JSON and serialize them with an optional filter.
///
/// # Safety
///
/// - `json_ptr` must point to a valid UTF-8 byte buffer of length `json_len`.
/// - `filter_ptr` may be null (no filter). If non-null, must point to valid JSON.
/// - `out_len` must point to a writable `usize`.
/// - The returned pointer must be freed with `aegis_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_load_and_serialize_findings(
    json_ptr: *const u8,
    json_len: usize,
    filter_ptr: *const u8,
    filter_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if json_ptr.is_null() || out_len.is_null() || json_len == 0 || json_len > MAX_INPUT_BYTES {
        return std::ptr::null_mut();
    }

    let input = unsafe { slice::from_raw_parts(json_ptr, json_len) };

    let findings: Vec<loader::FullFinding> = match serde_json::from_slice(input) {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(),
    };

    let filter = if !filter_ptr.is_null() && filter_len > 0 {
        if filter_len > MAX_FILTER_BYTES {
            // Reject oversized filters rather than silently dropping to unfiltered
            return std::ptr::null_mut();
        }
        let filter_bytes = unsafe { slice::from_raw_parts(filter_ptr, filter_len) };
        serde_json::from_slice::<loader::FindingsFilter>(filter_bytes).ok()
    } else {
        None
    };

    let output = match loader::serialize_findings(&findings, filter.as_ref()) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let boxed = output.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;

    unsafe { *out_len = len };
    ptr
}

/// Free a buffer previously returned by an `aegis_*` function.
///
/// # Safety
///
/// - `ptr` and `len` must exactly match a previous return from this library.
/// - Must not be called twice on the same pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aegis_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // Reconstruct the Box<[u8]> that was leaked via Box::into_raw.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_round_trip() {
        let input = r#"[
            {"id":"f1","resource_type":"compute","resource_id":"r1","resource_name":"EC2-1",
             "cloud_provider":"AWS","region":"us-east-1","account_id":"acct-1",
             "severity":"HIGH","category":"NETWORK","exploit_available":false,"mitre_tactics":[]},
            {"id":"f2","resource_type":"storage","resource_id":"r2","resource_name":"S3-1",
             "cloud_provider":"AWS","region":"us-east-1","account_id":"acct-1",
             "severity":"CRITICAL","category":"DATA","exploit_available":false,"mitre_tactics":[]}
        ]"#;

        let bytes = input.as_bytes();
        let mut out_len: usize = 0;

        let result_ptr =
            unsafe { aegis_compute_attack_paths(bytes.as_ptr(), bytes.len(), &mut out_len) };

        assert!(!result_ptr.is_null());
        assert!(out_len > 0);

        let result_bytes = unsafe { std::slice::from_raw_parts(result_ptr, out_len) };
        let result: types::AttackPathResult = serde_json::from_slice(result_bytes).unwrap();

        assert_eq!(result.paths.len(), 1);
        assert_eq!(result.stats.total_findings, 2);
        assert_eq!(result.stats.findings_in_paths, 2);

        unsafe { aegis_free(result_ptr, out_len) };
    }

    #[test]
    fn ffi_null_input() {
        let mut out_len: usize = 0;
        let ptr = unsafe { aegis_compute_attack_paths(std::ptr::null(), 0, &mut out_len) };
        assert!(ptr.is_null());
    }

    #[test]
    fn ffi_invalid_json() {
        let bad = b"not json";
        let mut out_len: usize = 0;
        let ptr =
            unsafe { aegis_compute_attack_paths(bad.as_ptr(), bad.len(), &mut out_len) };
        assert!(ptr.is_null());
    }

    #[test]
    fn ffi_rejects_oversized_input() {
        let small = b"[]";
        let mut out_len: usize = 0;
        // Pass a json_len exceeding MAX_INPUT_BYTES — guard returns null before deref
        let ptr = unsafe {
            aegis_compute_attack_paths(small.as_ptr(), MAX_INPUT_BYTES + 1, &mut out_len)
        };
        assert!(ptr.is_null());
    }

    #[test]
    fn ffi_loader_round_trip() {
        let input = r#"[{
            "id":"f-1","source":"test","source_finding_id":"sf","type":"vuln",
            "title":"T","description":"D","resource_type":"storage",
            "resource_id":"r1","resource_name":"S3","platform":"aws",
            "cloud_provider":"AWS","region":"us-east-1","account_id":"acct-1",
            "account_name":"prod","environment_type":"production",
            "static_severity":"HIGH","severity":"HIGH","category":"DATA","status":"ACTIVE"
        }]"#;

        let bytes = input.as_bytes();
        let mut out_len: usize = 0;

        let result_ptr = unsafe {
            aegis_load_and_serialize_findings(
                bytes.as_ptr(),
                bytes.len(),
                std::ptr::null(),
                0,
                &mut out_len,
            )
        };

        assert!(!result_ptr.is_null());
        assert!(out_len > 0);

        let result_bytes = unsafe { std::slice::from_raw_parts(result_ptr, out_len) };
        let parsed: Vec<loader::FullFinding> = serde_json::from_slice(result_bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "f-1");

        unsafe { aegis_free(result_ptr, out_len) };
    }
}
