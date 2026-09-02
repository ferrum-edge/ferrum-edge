//! `changelog.d/` fragment rules, enforced by the required `Unit Tests` job.
//!
//! Unreleased changelog entries live as one file per change under
//! `changelog.d/` instead of in `CHANGELOG.md`'s shared `[Unreleased]` block
//! (issue #4487). These tests re-implement the rules of
//! `scripts/assemble_changelog.py --check` in Rust over the real directory, so
//! a malformed fragment fails the required check with no workflow change.
//!
//! `std::fs` / `include_str!` inspection only — no runtime, no subprocess.

use std::fs;
use std::path::PathBuf;

const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");

const UNRELEASED_HEADING: &str = "## [Unreleased]";
const BREAKING_TOKEN: &str = "**BREAKING";

/// Keep a Changelog sections, in the order `CHANGELOG.md` already uses.
const CHANGELOG_SECTIONS: &[&str] = &[
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
];
const UPGRADE_SECTION: &str = "upgrade";

/// Files under `changelog.d/` that document the convention, not a change.
const NON_FRAGMENT_NAMES: &[&str] = &["README.md"];

fn fragment_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("changelog.d")
}

struct Fragment {
    name: String,
    section: String,
    reference: String,
    body: String,
}

impl Fragment {
    fn is_breaking(&self) -> bool {
        self.body.contains(BREAKING_TOKEN)
    }
}

fn is_valid_reference(reference: &str) -> bool {
    let digits = reference.strip_prefix("pr").unwrap_or(reference);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Fragment names, sorted, excluding the directory's own documentation.
fn fragment_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fragment_dir())
        .expect("changelog.d/ must exist")
        .map(|entry| entry.expect("readable changelog.d/ entry"))
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".md") && !NON_FRAGMENT_NAMES.contains(&name.as_str()))
        .collect();
    names.sort();
    names
}

/// Parse every fragment, collecting naming failures rather than panicking.
fn load_fragments() -> (Vec<Fragment>, Vec<String>) {
    let mut fragments = Vec::new();
    let mut failures = Vec::new();
    for name in fragment_names() {
        let stem = name.trim_end_matches(".md");
        let parts: Vec<&str> = stem.split('.').collect();
        if parts.len() != 2 {
            failures.push(format!(
                "changelog.d/{name}: malformed fragment name; expected \
                 <ref>.<section>.md, for example 4487.changed.md"
            ));
            continue;
        }
        let (reference, section) = (parts[0], parts[1]);
        if !is_valid_reference(reference) {
            failures.push(format!(
                "changelog.d/{name}: '{reference}' is not a valid reference; use the \
                 issue number (4487) or pr<N> when there is no issue"
            ));
            continue;
        }
        if section != UPGRADE_SECTION && !CHANGELOG_SECTIONS.contains(&section) {
            failures.push(format!(
                "changelog.d/{name}: unknown section '{section}'; valid sections are \
                 {}, {UPGRADE_SECTION}",
                CHANGELOG_SECTIONS.join(", ")
            ));
            continue;
        }
        let (reference, section) = (reference.to_string(), section.to_string());
        let body = fs::read_to_string(fragment_dir().join(&name))
            .unwrap_or_else(|err| panic!("changelog.d/{name} must be readable: {err}"));
        let body = body.replace("\r\n", "\n").trim_matches('\n').to_string();
        if body.trim().is_empty() {
            failures.push(format!("changelog.d/{name}: body is empty"));
            continue;
        }
        fragments.push(Fragment {
            name,
            section,
            reference,
            body,
        });
    }
    (fragments, failures)
}

/// Markdown link targets (`](target)`) in `body`.
fn link_targets(body: &str) -> Vec<&str> {
    let mut targets = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find("](") {
        rest = &rest[open + 2..];
        match rest.find(')') {
            Some(close) => {
                targets.push(rest[..close].trim());
                rest = &rest[close + 1..];
            }
            None => break,
        }
    }
    targets
}

fn unreleased_section(changelog: &str) -> Option<&str> {
    let after_heading = changelog.split(UNRELEASED_HEADING).nth(1)?;
    Some(match after_heading.find("\n## ") {
        Some(end) => &after_heading[..end],
        None => after_heading,
    })
}

#[test]
fn fragment_names_are_well_formed() {
    let (_, failures) = load_fragments();
    assert!(
        failures.is_empty(),
        "changelog.d/ fragment naming errors:\n{}",
        failures.join("\n")
    );
}

#[test]
fn changelog_fragments_hold_exactly_one_top_level_bullet() {
    let (fragments, _) = load_fragments();
    let mut failures = Vec::new();
    for fragment in &fragments {
        if fragment.section == UPGRADE_SECTION {
            continue;
        }
        let name = &fragment.name;
        let mut lines = fragment.body.lines();
        match lines.next() {
            Some(first) if first.starts_with("- ") => {}
            _ => {
                failures.push(format!(
                    "changelog.d/{name}: body must begin with one top-level bullet \
                     ('- ' at column 0)"
                ));
                continue;
            }
        }
        for (index, line) in lines.enumerate() {
            let number = index + 2;
            if line.starts_with("- ") {
                failures.push(format!(
                    "changelog.d/{name}: line {number} starts a second top-level \
                     bullet; one fragment holds exactly one bullet"
                ));
            } else if !line.trim().is_empty() && !line.starts_with("  ") {
                failures.push(format!(
                    "changelog.d/{name}: line {number} is a continuation line that is \
                     not indented two spaces"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn upgrade_fragments_are_upgrade_guide_blocks() {
    let (fragments, _) = load_fragments();
    let failures: Vec<String> = fragments
        .iter()
        .filter(|fragment| fragment.section == UPGRADE_SECTION)
        .filter(|fragment| !fragment.body.starts_with("### "))
        .map(|fragment| {
            format!(
                "changelog.d/{}: upgrade fragments must begin with a \
                 '### <heading> (issue [#N](...))' block",
                fragment.name
            )
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn fragment_links_are_absolute() {
    let (fragments, _) = load_fragments();
    let mut failures = Vec::new();
    for fragment in &fragments {
        for target in link_targets(&fragment.body) {
            if !target.starts_with("http://")
                && !target.starts_with("https://")
                && !target.starts_with('#')
            {
                failures.push(format!(
                    "changelog.d/{}: link target '{target}' is relative; use an \
                     absolute https://github.com/ferrum-edge/ferrum-edge/blob/main/... \
                     URL, because the fragment's text moves to the repository root at \
                     release time",
                    fragment.name
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn breaking_fragments_pair_with_upgrade_fragments() {
    let (fragments, _) = load_fragments();
    let upgrade_refs: Vec<&str> = fragments
        .iter()
        .filter(|fragment| fragment.section == UPGRADE_SECTION)
        .map(|fragment| fragment.reference.as_str())
        .collect();
    let breaking_refs: Vec<&str> = fragments
        .iter()
        .filter(|fragment| fragment.section != UPGRADE_SECTION && fragment.is_breaking())
        .map(|fragment| fragment.reference.as_str())
        .collect();

    let mut failures = Vec::new();
    for fragment in &fragments {
        if fragment.section != UPGRADE_SECTION
            && fragment.is_breaking()
            && !upgrade_refs.contains(&fragment.reference.as_str())
        {
            failures.push(format!(
                "changelog.d/{}: a {BREAKING_TOKEN} bullet needs upgrade guidance; add \
                 changelog.d/{}.upgrade.md",
                fragment.name, fragment.reference
            ));
        }
        if fragment.section == UPGRADE_SECTION
            && !breaking_refs.contains(&fragment.reference.as_str())
        {
            failures.push(format!(
                "changelog.d/{}: upgrade guidance without a {BREAKING_TOKEN} changelog \
                 bullet for '{}'",
                fragment.name, fragment.reference
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn committed_unreleased_section_is_empty() {
    let unreleased = unreleased_section(CHANGELOG)
        .expect("CHANGELOG.md must contain an ## [Unreleased] heading");
    assert!(
        unreleased.trim().is_empty(),
        "CHANGELOG.md '{UNRELEASED_HEADING}' must stay empty between releases; \
         unreleased entries live in changelog.d/ fragments and are assembled by \
         'scripts/assemble_changelog.py --release'. Found:\n{}",
        unreleased.trim()
    );
}

#[test]
fn fragment_helpers_match_the_documented_rules() {
    assert!(is_valid_reference("4487"));
    assert!(is_valid_reference("pr4501"));
    assert!(!is_valid_reference("pr"));
    assert!(!is_valid_reference("abc"));
    assert!(!is_valid_reference(""));

    assert_eq!(
        link_targets("see [a](https://x) and [b](docs/y.md)"),
        vec!["https://x", "docs/y.md"]
    );
    assert!(link_targets("no links here").is_empty());
    assert!(link_targets("unterminated [a](https://x").is_empty());

    assert_eq!(
        unreleased_section("## [Unreleased]\n\n## [1.0.0]\n"),
        Some("\n\n")
    );
    assert_eq!(unreleased_section("# Changelog\n"), None);
}
