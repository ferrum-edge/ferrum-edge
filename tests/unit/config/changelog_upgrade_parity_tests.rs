//! Unreleased `BREAKING` changelog entries must ship upgrade guidance.
//!
//! Unreleased entries live as one file per change under `changelog.d/` rather
//! than in `CHANGELOG.md`'s shared `[Unreleased]` block (issue #4487), so this
//! contract reads the fragments: every `BREAKING` changelog fragment must cite
//! an issue number, and every such number must appear either in the released
//! `docs/upgrade_guide.md` or in a `changelog.d/<ref>.upgrade.md` fragment
//! awaiting the next release. A `BREAKING` entry without a citation, or without
//! upgrade guidance, fails CI. The count of entries is not hard-coded.
//!
//! `include_str!` / `std::fs` inspection only — no runtime.

use std::fs;
use std::path::PathBuf;

const UPGRADE_GUIDE: &str = include_str!("../../../docs/upgrade_guide.md");
const MIGRATIONS_DOC: &str = include_str!("../../../docs/migrations.md");

/// Present while build-out folds core schema into the editable `V001` baseline.
const BUILD_OUT_BASELINE_POLICY_MARKER: &str = "folded into the current baseline schema (`V001`)";

/// Phrases that imply an in-place or automatic **core database schema** migration
/// workflow. Must stay absent from the upgrade guide while `MIGRATIONS_DOC`
/// still states the build-out baseline-only policy above.
const IN_PLACE_CORE_SCHEMA_MIGRATION_CLAIMS: &[&str] = &[
    "auto-migrates forward",
    "Let the new binary auto-migrate on startup",
    "Run migrations in dry-run mode before applying",
    "schema migrations may alter your database",
    "pending migrations automatically on startup",
];

fn fragment_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("changelog.d")
}

/// `changelog.d/` fragment file names, sorted, excluding the directory's README.
fn fragment_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fragment_dir())
        .expect("changelog.d/ must exist")
        .map(|entry| entry.expect("readable changelog.d/ entry"))
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".md") && name != "README.md")
        .collect();
    names.sort();
    names
}

fn read_fragment(name: &str) -> String {
    fs::read_to_string(fragment_dir().join(name))
        .unwrap_or_else(|err| panic!("changelog.d/{name} must be readable: {err}"))
        .replace("\r\n", "\n")
}

/// Changelog bullets awaiting release: every fragment but the `.upgrade.md` ones.
fn unreleased_bullets() -> Vec<String> {
    fragment_names()
        .iter()
        .filter(|name| !name.ends_with(".upgrade.md"))
        .map(|name| read_fragment(name).trim_end().to_string())
        .collect()
}

/// The released upgrade guide plus every `changelog.d/<ref>.upgrade.md` fragment.
fn upgrade_guidance() -> String {
    let mut guidance = String::from(UPGRADE_GUIDE);
    for name in fragment_names() {
        if name.ends_with(".upgrade.md") {
            guidance.push('\n');
            guidance.push_str(&read_fragment(&name));
        }
    }
    guidance
}

fn is_breaking_bullet(bullet: &str) -> bool {
    bullet.contains("**BREAKING")
}

/// Issue numbers from the first `(issue #N)` / `(issues #A / #B)` citation.
fn breaking_issue_numbers(bullet: &str) -> Result<Vec<u32>, String> {
    let head: String = bullet.chars().take(400).collect();
    let lower = head.to_ascii_lowercase();
    let citation_at = lower.find("(issue").ok_or_else(|| {
        let title = bullet.lines().next().unwrap_or(bullet);
        format!("Unreleased BREAKING fragment has no issue number: {title}")
    })?;
    let after_open = &head[citation_at..];
    let close = after_open.find(')').ok_or_else(|| {
        let title = bullet.lines().next().unwrap_or(bullet);
        format!("Unreleased BREAKING fragment has an unclosed issue citation: {title}")
    })?;
    let citation = &after_open[..close];
    let mut numbers = Vec::new();
    let bytes = citation.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j == i + 1 {
                let title = bullet.lines().next().unwrap_or(bullet);
                return Err(format!(
                    "Unreleased BREAKING fragment issue citation is missing digits: {title}"
                ));
            }
            let n: u32 = citation[i + 1..j].parse().map_err(|_| {
                let title = bullet.lines().next().unwrap_or(bullet);
                format!("Unreleased BREAKING fragment issue citation is not a number: {title}")
            })?;
            if !numbers.contains(&n) {
                numbers.push(n);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if numbers.is_empty() {
        let title = bullet.lines().next().unwrap_or(bullet);
        return Err(format!(
            "Unreleased BREAKING fragment issue citation contains no #NNNN: {title}"
        ));
    }
    Ok(numbers)
}

/// True when `guide` contains an exact `#NNNN` issue reference, not a longer
/// digit prefix such as `#32970` satisfying a search for `#3297`.
fn upgrade_guide_cites_issue(guide: &str, number: u32) -> bool {
    let needle = format!("#{number}");
    let mut start = 0;
    while let Some(rel) = guide[start..].find(&needle) {
        let at = start + rel;
        let after = at + needle.len();
        if after >= guide.len() || !guide.as_bytes()[after].is_ascii_digit() {
            return true;
        }
        start = at + 1;
    }
    false
}

#[test]
fn upgrade_guide_issue_reference_matcher_is_token_exact() {
    let pass_cases = [
        ("issue #3297", 3297),
        (
            "(issue [#3297](https://github.com/ferrum-edge/ferrum-edge/issues/3297))",
            3297,
        ),
        ("see #3297.", 3297),
        ("prefix #3297", 3297),
    ];
    for (guide, number) in pass_cases {
        assert!(
            upgrade_guide_cites_issue(guide, number),
            "expected #{number} in {guide:?}"
        );
    }

    let fail_cases = [
        ("issue #32970", 3297),
        ("#32970", 3297),
        ("digits3297suffix", 3297),
        ("no issue reference here", 3297),
    ];
    for (guide, number) in fail_cases {
        assert!(
            !upgrade_guide_cites_issue(guide, number),
            "did not expect exact #{number} in {guide:?}"
        );
    }
}

#[test]
fn unreleased_breaking_changelog_issues_appear_in_upgrade_guidance() {
    let guidance = upgrade_guidance();
    let mut missing_guidance = Vec::new();

    for bullet in unreleased_bullets() {
        if !is_breaking_bullet(&bullet) {
            continue;
        }
        let numbers = breaking_issue_numbers(&bullet).unwrap_or_else(|err| panic!("{err}"));
        for number in numbers {
            if !upgrade_guide_cites_issue(&guidance, number) {
                let title = bullet.lines().next().unwrap_or(&bullet);
                missing_guidance.push(format!("#{number} ({title})"));
            }
        }
    }

    assert!(
        missing_guidance.is_empty(),
        "every BREAKING changelog.d/ fragment issue number must appear in \
         docs/upgrade_guide.md or in a changelog.d/<ref>.upgrade.md fragment; \
         missing: {}",
        missing_guidance.join(", ")
    );
}

#[test]
fn upgrade_guide_does_not_claim_in_place_migration_during_build_out() {
    if !MIGRATIONS_DOC.contains(BUILD_OUT_BASELINE_POLICY_MARKER) {
        return;
    }

    let violations: Vec<&str> = IN_PLACE_CORE_SCHEMA_MIGRATION_CLAIMS
        .iter()
        .copied()
        .filter(|phrase| UPGRADE_GUIDE.contains(phrase))
        .collect();

    assert!(
        violations.is_empty(),
        "docs/upgrade_guide.md must not claim in-place/automatic core schema \
         migration while docs/migrations.md states build-out baseline-only \
         policy; found: {}",
        violations.join(", ")
    );
}
