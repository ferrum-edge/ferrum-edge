//! Vendor integrity (drift) guard.
//!
//! Ferrum Edge carries vendored, patched copies of upstream crates under
//! `vendor/**` (reqwest, h3, tungstenite, tokio-tungstenite, dimpl — see
//! `docs/dependency-policy.md` and `docs/upstream-*-patches/`). Those copies are
//! a supply-chain surface: any byte of them ships in the binary. This test pins
//! their contents to a committed manifest so vendored code cannot drift beyond
//! the documented patches without the change being forced into review.
//!
//! A failure means a file under `vendor/` was added, removed, or modified
//! without regenerating the manifest. If the change is an intentional patch
//! refresh, update the matching `docs/upstream-*-patches/` notes and regenerate:
//!
//! ```text
//! UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity
//! # or: scripts/update_vendor_integrity.sh
//! ```
//!
//! The guard compares the *data* — the set of (repo-relative path, content hash)
//! pairs — not the manifest's byte layout, so the on-disk header, ordering, and
//! whitespace are cosmetic.
//!
//! Hashing contract:
//! - Known text paths (allowlisted extensions / basenames) use SHA-256 over
//!   LF-normalized bytes (`\r` stripped) so CRLF checkouts stay stable.
//! - Every other path — including `.der` / `.bin` artifacts and any
//!   unrecognized extension — is hashed byte-for-byte. Classification is
//!   fail-safe: unknown paths default to byte-exact hashing so CR bytes in
//!   binary data cannot be added, removed, or altered unnoticed.
//!
//! Crate-local `Cargo.lock` files under `vendor/` are ignored by default because
//! documented standalone vendor tests (`cargo test --manifest-path
//! vendor/.../Cargo.toml`) can create them as incidental local outputs. Explicit
//! exceptions live in [`GOVERNED_VENDOR_LOCKFILES`]: those committed lockfiles
//! pin a standalone regression dependency graph and must appear in the manifest.
//!
//! `.expect()`/`.unwrap()` are used freely here per the test-code exemption.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_REL: &str = "vendor/VENDOR_INTEGRITY.sha256";
const VENDOR_REL: &str = "vendor";

/// Repo-relative paths of committed vendor `Cargo.lock` files that pin a
/// documented standalone regression dependency graph and are therefore part of
/// the governed supply-chain surface.
///
/// All other crate-local `Cargo.lock` files under `vendor/` remain ignored so
/// incidental lockfiles from documented standalone tests for other vendored
/// crates do not cause false drift failures. Prefer extending this allowlist
/// over parent-name heuristics when a new vendor lockfile is intentionally
/// committed.
const GOVERNED_VENDOR_LOCKFILES: &[&str] = &["vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock"];

fn repo_root() -> PathBuf {
    // Runtime lookup (not `env!`) so this resolves correctly when the test runs
    // from a prebuilt nextest archive on a different runner via
    // `--workspace-remap` — nextest sets CARGO_MANIFEST_DIR to the remapped
    // location at runtime, whereas `env!` would bake in the build host's path.
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
}

/// Whether a repo-relative path under `vendor/` participates in the drift
/// manifest. Non-lockfile paths are always included (aside from the manifest
/// itself, which `compute_entries` drops). `Cargo.lock` paths are included only
/// when listed in [`GOVERNED_VENDOR_LOCKFILES`].
fn should_hash_vendor_file(rel_path: &str) -> bool {
    let name = Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if name == "Cargo.lock" {
        return GOVERNED_VENDOR_LOCKFILES.contains(&rel_path);
    }
    true
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read vendor dir") {
        let path = entry.expect("vendor dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Skip build output from running the documented standalone vendor
            // tests (`cargo test --manifest-path vendor/.../Cargo.toml`), which
            // is not part of the vendored patch.
            if name == "target" {
                continue;
            }
            collect_files(root, &path, out);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("vendor path under repo root")
                .to_string_lossy()
                .replace('\\', "/");
            // Skip incidental crate-local lockfiles; keep allowlisted ones.
            if !should_hash_vendor_file(&rel) {
                continue;
            }
            out.push(path);
        }
    }
}

/// Whether `path` is a known vendored text path eligible for LF normalization.
///
/// Only an explicit allowlist of source/docs/config basenames and extensions is
/// treated as text. Unrecognized paths — including binary artifacts such as
/// `.der` / `.bin` and any future unknown extension — return `false` so they
/// are hashed byte-for-byte (fail-closed for unrecognized data).
fn vendor_path_uses_lf_normalization(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "LICENSE" | "LICENSE-MIT" | "LICENSE-APACHE" | ".gitignore" | ".cargo-ok" => {
            return true;
        }
        _ => {}
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(
        ext,
        "rs" | "md" | "toml" | "yml" | "yaml" | "json" | "txt" | "sh" | "lock" | "orig"
    )
}

/// SHA-256 for a vendor file under the text/binary hashing contract.
///
/// Text paths strip `\r` before hashing (matches `tr -d '\r' | shasum -a 256`)
/// so CRLF checkouts of vendored sources stay stable. Binary and unrecognized
/// paths hash the on-disk bytes unchanged.
fn hash_vendor_bytes(path: &Path, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    if vendor_path_uses_lf_normalization(path) {
        let normalized: Vec<u8> = bytes.iter().copied().filter(|b| *b != b'\r').collect();
        hasher.update(&normalized);
    } else {
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

fn hash_vendor_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read vendor file");
    hash_vendor_bytes(path, &bytes)
}

/// The authoritative comparison set: repo-relative vendor path -> content hash.
fn compute_entries() -> BTreeMap<String, String> {
    let root = repo_root();
    let vendor = root.join(VENDOR_REL);
    let manifest_abs = root.join(MANIFEST_REL);

    let mut files = Vec::new();
    collect_files(&root, &vendor, &mut files);
    files.retain(|p| *p != manifest_abs);

    files
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("vendor path under repo root")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, hash_vendor_file(p))
        })
        .collect()
}

/// Parse a manifest into the same path -> hash map, ignoring comments, blank
/// lines, ordering, and surrounding whitespace. Row format: `<hash>  <path>`.
fn parse_manifest(s: &str) -> BTreeMap<String, String> {
    s.lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut it = l.splitn(2, "  ");
            let hash = it.next()?.trim().to_string();
            let path = it.next()?.trim().to_string();
            if hash.is_empty() || path.is_empty() {
                return None;
            }
            Some((path, hash))
        })
        .collect()
}

fn render_manifest(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    out.push_str("# Vendor integrity manifest — SHA-256 of governed vendor file contents.\n");
    out.push_str(
        "# Text (allowlisted) paths: LF-normalized (CR stripped). Binary/unrecognized: byte-exact.\n",
    );
    out.push_str("# Compared as (path, hash) data; header/order/whitespace are cosmetic.\n");
    out.push_str("# Regenerate: scripts/update_vendor_integrity.sh  (docs/dependency-policy.md)\n");
    for (path, hash) in entries {
        out.push_str(&format!("{hash}  {path}\n"));
    }
    out
}

fn first_differences(
    existing: &BTreeMap<String, String>,
    computed: &BTreeMap<String, String>,
) -> String {
    let mut msgs = Vec::new();
    for (path, hb) in computed {
        match existing.get(path) {
            None => msgs.push(format!("  + added/unlisted: {path}")),
            Some(ha) if ha != hb => msgs.push(format!("  ~ modified:      {path}")),
            _ => {}
        }
    }
    for path in existing.keys() {
        if !computed.contains_key(path) {
            msgs.push(format!("  - removed:       {path}"));
        }
    }
    msgs.sort();
    msgs.truncate(25);
    if msgs.is_empty() {
        "  (no path/hash differences — check the manifest is non-empty)".to_string()
    } else {
        msgs.join("\n")
    }
}

#[test]
fn vendor_integrity_manifest_matches() {
    let manifest_abs = repo_root().join(MANIFEST_REL);
    let computed = compute_entries();

    if std::env::var_os("UPDATE_VENDOR_INTEGRITY").is_some() {
        fs::write(&manifest_abs, render_manifest(&computed)).expect("write vendor manifest");
        eprintln!("Regenerated {MANIFEST_REL} ({} entries)", computed.len());
        return;
    }

    let existing_text = fs::read_to_string(&manifest_abs).unwrap_or_else(|e| {
        panic!(
            "missing {MANIFEST_REL}: {e}\n\
             Generate it with:\n  \
             UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity"
        )
    });
    let existing = parse_manifest(&existing_text);

    assert!(
        existing == computed,
        "Vendored crate contents changed but {MANIFEST_REL} was not regenerated.\n\
         This guards vendor/** against drift beyond the documented patches \
         (see docs/dependency-policy.md).\n\
         If this is an intentional patch refresh, update the relevant \
         docs/upstream-*-patches/ notes and regenerate the manifest:\n  \
         UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity\n\n\
         Changes detected:\n{}",
        first_differences(&existing, &computed)
    );
}

#[test]
fn governed_vendor_lockfile_allowlist_includes_dimpl() {
    assert!(should_hash_vendor_file(
        "vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock"
    ));
    assert!(
        GOVERNED_VENDOR_LOCKFILES.contains(&"vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock"),
        "dimpl's committed standalone regression lockfile must stay allowlisted"
    );
}

#[test]
fn incidental_vendor_lockfiles_are_not_hashed() {
    // Documented standalone tests for other vendored crates may create these
    // locally; they must not enter the drift set unless intentionally committed
    // and added to GOVERNED_VENDOR_LOCKFILES.
    for path in [
        "vendor/h3-0.0.8-ferrum-patched/Cargo.lock",
        "vendor/reqwest-0.13.3-ferrum-patched/Cargo.lock",
        "vendor/tungstenite-0.29.0-ferrum-patched/Cargo.lock",
        "vendor/tokio-tungstenite-0.29.0-ferrum-patched/Cargo.lock",
    ] {
        assert!(
            !should_hash_vendor_file(path),
            "incidental lockfile must stay ignored: {path}"
        );
    }
}

#[test]
fn non_lockfile_vendor_paths_remain_hashed() {
    assert!(should_hash_vendor_file(
        "vendor/dimpl-0.6.1-ferrum-patched/Cargo.toml"
    ));
    assert!(should_hash_vendor_file(
        "vendor/h3-0.0.8-ferrum-patched/src/lib.rs"
    ));
}

#[test]
fn known_text_vendor_paths_use_lf_normalization() {
    for path in [
        "vendor/dimpl-0.6.1-ferrum-patched/src/lib.rs",
        "vendor/dimpl-0.6.1-ferrum-patched/Cargo.toml",
        "vendor/dimpl-0.6.1-ferrum-patched/Cargo.toml.orig",
        "vendor/dimpl-0.6.1-ferrum-patched/Cargo.lock",
        "vendor/dimpl-0.6.1-ferrum-patched/.gitignore",
        "vendor/dimpl-0.6.1-ferrum-patched/.cargo-ok",
        "vendor/h3-0.0.8-ferrum-patched/LICENSE",
        "vendor/reqwest-0.13.3-ferrum-patched/LICENSE-MIT",
        "vendor/reqwest-0.13.3-ferrum-patched/LICENSE-APACHE",
        "vendor/dimpl-0.6.1-ferrum-patched/.cargo_vcs_info.json",
        "docs/note.md",
        "script.sh",
        "config.yml",
        "config.yaml",
        "notes.txt",
    ] {
        assert!(
            vendor_path_uses_lf_normalization(Path::new(path)),
            "expected LF normalization for text path: {path}"
        );
    }
}

#[test]
fn binary_and_unrecognized_vendor_paths_are_byte_exact() {
    for path in [
        "vendor/dimpl-0.6.1-ferrum-patched/src/crypto/validation/p256_cert.der",
        "vendor/dimpl-0.6.1-ferrum-patched/src/crypto/validation/test_data.bin",
        "vendor/dimpl-0.6.1-ferrum-patched/src/crypto/validation/p384_sha384_sig.der",
        "vendor/future-crate/unknown.blob",
        "vendor/future-crate/data.wasm",
        "vendor/future-crate/no_extension_payload",
    ] {
        assert!(
            !vendor_path_uses_lf_normalization(Path::new(path)),
            "expected byte-exact hashing for binary/unrecognized path: {path}"
        );
    }
}

#[test]
fn text_hash_strips_cr_bytes_but_binary_hash_preserves_them() {
    // Identical payload with an embedded CR: text normalization must hide it,
    // binary hashing must pin it.
    let with_cr = b"alpha\r\nbeta\r";
    let without_cr = b"alpha\nbeta";

    let text_path = Path::new("vendor/example/src/lib.rs");
    let binary_path = Path::new("vendor/example/assets/fixture.der");

    assert_eq!(
        hash_vendor_bytes(text_path, with_cr),
        hash_vendor_bytes(text_path, without_cr),
        "text paths must LF-normalize before hashing"
    );
    assert_ne!(
        hash_vendor_bytes(binary_path, with_cr),
        hash_vendor_bytes(binary_path, without_cr),
        "binary paths must hash CR bytes byte-for-byte"
    );

    // Spot-check against the system digest for the binary contract.
    let mut hasher = Sha256::new();
    hasher.update(with_cr);
    assert_eq!(
        hash_vendor_bytes(binary_path, with_cr),
        hex::encode(hasher.finalize())
    );
}
