//! Vendor integrity (drift) guard.
//!
//! Ferrum Edge carries vendored, patched copies of upstream crates under
//! `vendor/**` (reqwest, h3, tungstenite, tokio-tungstenite — see
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
//! whitespace are cosmetic. Content hash is SHA-256 over LF-normalized bytes.
//!
//! `.expect()`/`.unwrap()` are used freely here per the test-code exemption.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_REL: &str = "vendor/VENDOR_INTEGRITY.sha256";
const VENDOR_REL: &str = "vendor";

fn repo_root() -> PathBuf {
    // Runtime lookup (not `env!`) so this resolves correctly when the test runs
    // from a prebuilt nextest archive on a different runner via
    // `--workspace-remap` — nextest sets CARGO_MANIFEST_DIR to the remapped
    // location at runtime, whereas `env!` would bake in the build host's path.
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
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
            collect_files(&path, out);
        } else if path.is_file() {
            // Skip crate-local lockfiles that those same standalone test commands
            // generate; they aren't part of the vendored sources and would
            // otherwise cause a false drift failure for local developers.
            if name == "Cargo.lock" {
                continue;
            }
            out.push(path);
        }
    }
}

/// SHA-256 over LF-normalized bytes. Stripping `\r` means a CRLF checkout on a
/// Windows dev box doesn't spuriously trip the guard — vendored upstream sources
/// are LF, and we only need stable, reproducible digests for drift detection,
/// not byte-faithful file hashes. (Matches `tr -d '\r' | shasum -a 256`.)
fn hash_normalized(path: &Path) -> String {
    let bytes = fs::read(path).expect("read vendor file");
    let normalized: Vec<u8> = bytes.into_iter().filter(|b| *b != b'\r').collect();
    let mut hasher = Sha256::new();
    hasher.update(&normalized);
    hex::encode(hasher.finalize())
}

/// The authoritative comparison set: repo-relative vendor path -> content hash.
fn compute_entries() -> BTreeMap<String, String> {
    let root = repo_root();
    let vendor = root.join(VENDOR_REL);
    let manifest_abs = root.join(MANIFEST_REL);

    let mut files = Vec::new();
    collect_files(&vendor, &mut files);
    files.retain(|p| *p != manifest_abs);

    files
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("vendor path under repo root")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, hash_normalized(p))
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
    out.push_str("# Vendor integrity manifest — SHA-256 of LF-normalized file contents.\n");
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
