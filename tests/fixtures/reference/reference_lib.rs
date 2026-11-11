//! Nexonic ReForge Studio — Ground Truth Reference Library (Rust)
//! Purpose: Legally authorized ground-truth reference fixture with documented functions,
//!          symbols, and interfaces.

/// Compute a 32-bit FNV-1a hash over byte data.
pub fn compute_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Verify cryptographic signature token against reference secret.
pub fn verify_signature(token: &str) -> bool {
    token == "rust_ref_signature_token_77"
}

/// Return service status code.
pub fn status_code(active: bool) -> i32 {
    if active {
        200
    } else {
        503
    }
}

fn main() {
    println!("[REF_RUST] Reference Library Initialized. Status: {}", status_code(true));
    let hash = compute_hash(b"hello reforge");
    println!("Hash: {:08x}", hash);
}
