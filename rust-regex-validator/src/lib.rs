use regex::Regex;
use std::cell::RefCell;
use std::mem;
use std::slice;
use std::str;

thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static LAST_MATCHES: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static LAST_SCAN_TRUNCATED: RefCell<bool> = const { RefCell::new(false) };
}

struct ScanResult {
    offsets: Vec<u32>,
    truncated: bool,
}

fn scan_offsets(pattern: &str, text: &str, max_matches: usize) -> Result<ScanResult, regex::Error> {
    let regex = Regex::new(pattern)?;
    let mut offsets = Vec::with_capacity(max_matches.saturating_mul(2));
    let mut truncated = false;
    for (index, found) in regex.find_iter(text).enumerate() {
        if index == max_matches {
            truncated = true;
            break;
        }
        offsets.push(found.start() as u32);
        offsets.push(found.end() as u32);
    }
    Ok(ScanResult { offsets, truncated })
}

fn set_error(message: impl AsRef<str>) {
    LAST_ERROR.with(|error| {
        let mut error = error.borrow_mut();
        error.clear();
        error.extend_from_slice(message.as_ref().as_bytes());
    });
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len);
    let pointer = buffer.as_mut_ptr();
    mem::forget(buffer);
    pointer
}

#[no_mangle]
/// Releases a buffer previously returned by [`alloc`].
///
/// # Safety
///
/// `pointer` must have been returned by `alloc(capacity)`, must not already have
/// been released, and `capacity` must be the exact capacity used for allocation.
pub unsafe extern "C" fn dealloc(pointer: *mut u8, capacity: usize) {
    if capacity != 0 {
        drop(unsafe { Vec::from_raw_parts(pointer, 0, capacity) });
    }
}

#[no_mangle]
/// Compiles the UTF-8 regex stored in the caller-owned Wasm buffer.
///
/// # Safety
///
/// `pointer` must be valid for reads of `len` bytes for the duration of this
/// call. The pointed-to bytes may be arbitrary; invalid UTF-8 is reported.
pub unsafe extern "C" fn validate(pointer: *const u8, len: usize) -> i32 {
    let bytes = unsafe { slice::from_raw_parts(pointer, len) };
    let pattern = match str::from_utf8(bytes) {
        Ok(pattern) => pattern,
        Err(error) => {
            set_error(format!("regex source is not valid UTF-8: {error}"));
            return 0;
        }
    };

    match Regex::new(pattern) {
        Ok(_) => {
            set_error("");
            1
        }
        Err(error) => {
            set_error(error.to_string());
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn error_ptr() -> *const u8 {
    LAST_ERROR.with(|error| error.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn error_len() -> usize {
    LAST_ERROR.with(|error| error.borrow().len())
}

#[no_mangle]
/// Scans UTF-8 pattern/text buffers and stores byte-offset pairs for retrieval.
///
/// # Safety
///
/// Both pointers must be valid for reads of their corresponding lengths for the
/// duration of this call.
pub unsafe extern "C" fn scan(
    pattern_pointer: *const u8,
    pattern_len: usize,
    text_pointer: *const u8,
    text_len: usize,
    max_matches: usize,
) -> i32 {
    let pattern =
        match str::from_utf8(unsafe { slice::from_raw_parts(pattern_pointer, pattern_len) }) {
            Ok(pattern) => pattern,
            Err(error) => {
                set_error(format!("regex source is not valid UTF-8: {error}"));
                return 0;
            }
        };
    let text = match str::from_utf8(unsafe { slice::from_raw_parts(text_pointer, text_len) }) {
        Ok(text) => text,
        Err(error) => {
            set_error(format!("sample text is not valid UTF-8: {error}"));
            return 0;
        }
    };

    match scan_offsets(pattern, text, max_matches.min(500)) {
        Ok(result) => {
            LAST_MATCHES.with(|matches| *matches.borrow_mut() = result.offsets);
            LAST_SCAN_TRUNCATED.with(|truncated| *truncated.borrow_mut() = result.truncated);
            set_error("");
            1
        }
        Err(error) => {
            LAST_MATCHES.with(|matches| matches.borrow_mut().clear());
            LAST_SCAN_TRUNCATED.with(|truncated| *truncated.borrow_mut() = false);
            set_error(error.to_string());
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn matches_ptr() -> *const u32 {
    LAST_MATCHES.with(|matches| matches.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn matches_len() -> usize {
    LAST_MATCHES.with(|matches| matches.borrow().len())
}

#[no_mangle]
pub extern "C" fn scan_truncated() -> i32 {
    LAST_SCAN_TRUNCATED.with(|truncated| i32::from(*truncated.borrow()))
}

#[cfg(test)]
mod tests {
    use super::scan_offsets;
    use std::time::{Duration, Instant};

    #[test]
    fn scan_offsets_are_bounded_and_correct() {
        let result = scan_offsets("(a|aa){1,35}b", "xx aab yy aaab", 1).unwrap();
        assert_eq!(result.offsets, vec![3, 6]);
        assert!(result.truncated);
    }

    #[test]
    fn ambiguous_alternation_is_linear_time() {
        let text = "a".repeat(60_000);
        let started = Instant::now();
        let result = scan_offsets("(a|aa){1,35}b", &text, 500).unwrap();
        assert!(result.offsets.is_empty());
        assert!(!result.truncated);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
