//! Coverage matrix emission.
//!
//! Drains the [`super::registry`] and writes two artifacts to
//! `target/conformance/`:
//!   - `coverage.json` — machine-readable matrix consumable by dashboards or
//!     CI gates.
//!   - `coverage.md` — human-readable Markdown table operators paste into
//!     PRs / status pages.
//!
//! Both files are written atomically (write to `.tmp`, rename) so a concurrent
//! `cat target/conformance/coverage.md` never observes a partial line.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use super::registry::{Feature, Status, snapshot};

const ARTIFACT_DIR: &str = "target/conformance";

#[derive(Debug, Serialize)]
struct CoverageReport {
    summary: CoverageSummary,
    categories: Vec<CategoryReport>,
}

#[derive(Debug, Serialize)]
struct CoverageSummary {
    total: usize,
    supported: usize,
    deferred: usize,
    out_of_scope: usize,
    /// Per-category histogram so operators can drill down without parsing the
    /// full feature list.
    by_category: BTreeMap<String, CategorySummary>,
}

#[derive(Debug, Serialize, Default)]
struct CategorySummary {
    total: usize,
    supported: usize,
    deferred: usize,
    out_of_scope: usize,
}

#[derive(Debug, Serialize)]
struct CategoryReport {
    name: String,
    features: Vec<FeatureEntry>,
}

#[derive(Debug, Serialize)]
struct FeatureEntry {
    name: String,
    status: String,
    test: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

/// Drain the registry and write `coverage.json` + `coverage.md` to
/// `target/conformance/`.
pub(crate) fn emit_artifacts() -> std::io::Result<()> {
    let features = snapshot();

    // Group by category — registry stores a `BTreeMap`, so ordering is
    // already deterministic by `(category, feature)`. We rebuild the
    // category map here so the reporter doesn't reach into registry
    // internals.
    let mut categories: BTreeMap<&'static str, Vec<&Feature>> = BTreeMap::new();
    for feature in &features {
        categories
            .entry(feature.category)
            .or_default()
            .push(feature);
    }

    let mut by_category = BTreeMap::new();
    let mut total = 0;
    let mut supported = 0;
    let mut deferred = 0;
    let mut out_of_scope = 0;

    let mut category_reports = Vec::with_capacity(categories.len());
    for (category, items) in &categories {
        let mut cat_summary = CategorySummary {
            total: items.len(),
            ..CategorySummary::default()
        };
        let mut feature_entries = Vec::with_capacity(items.len());
        for feature in items {
            match feature.status {
                Status::Supported => {
                    supported += 1;
                    cat_summary.supported += 1;
                }
                Status::Deferred => {
                    deferred += 1;
                    cat_summary.deferred += 1;
                }
                Status::OutOfScope => {
                    out_of_scope += 1;
                    cat_summary.out_of_scope += 1;
                }
            }
            total += 1;
            feature_entries.push(FeatureEntry {
                name: feature.feature.clone(),
                status: status_str(feature.status).to_string(),
                test: feature.test_name.to_string(),
                notes: feature.notes.clone(),
            });
        }
        by_category.insert((*category).to_string(), cat_summary);
        category_reports.push(CategoryReport {
            name: (*category).to_string(),
            features: feature_entries,
        });
    }

    let report = CoverageReport {
        summary: CoverageSummary {
            total,
            supported,
            deferred,
            out_of_scope,
            by_category,
        },
        categories: category_reports,
    };

    let dir = PathBuf::from(ARTIFACT_DIR);
    fs::create_dir_all(&dir)?;

    write_atomic(&dir.join("coverage.json"), |w| {
        serde_json::to_writer_pretty(w, &report).map_err(std::io::Error::other)
    })?;

    write_atomic(&dir.join("coverage.md"), |w| render_markdown(w, &report))?;

    Ok(())
}

fn status_str(status: Status) -> &'static str {
    match status {
        Status::Supported => "supported",
        Status::Deferred => "deferred",
        Status::OutOfScope => "out_of_scope",
    }
}

fn write_atomic<F>(path: &std::path::Path, render: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::fs::File) -> std::io::Result<()>,
{
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("tmp")
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        render(&mut f)?;
        f.flush()?;
    }
    fs::rename(tmp, path)
}

fn render_markdown(w: &mut std::fs::File, report: &CoverageReport) -> std::io::Result<()> {
    writeln!(w, "# Ferrum Edge Conformance Coverage")?;
    writeln!(w)?;
    writeln!(
        w,
        "Auto-generated by `cargo test --test conformance_tests`."
    )?;
    writeln!(
        w,
        "Edit the underlying conformance test source under `tests/conformance/` \
         to add or update coverage."
    )?;
    writeln!(w)?;
    writeln!(w, "## Summary")?;
    writeln!(w)?;
    writeln!(w, "| Metric | Count |")?;
    writeln!(w, "|---|---|")?;
    writeln!(w, "| Total features asserted | {} |", report.summary.total)?;
    writeln!(w, "| Supported | {} |", report.summary.supported)?;
    writeln!(w, "| Deferred | {} |", report.summary.deferred)?;
    writeln!(w, "| Out of scope | {} |", report.summary.out_of_scope)?;
    writeln!(w)?;

    writeln!(w, "## Status reference")?;
    writeln!(w)?;
    writeln!(
        w,
        "- **supported** — Ferrum Edge implements the feature as documented; \
         the test asserts the expected behavior."
    )?;
    writeln!(
        w,
        "- **deferred** — A known gap. The test records the expected \
         behavior; the notes describe the tracking work."
    )?;
    writeln!(
        w,
        "- **out_of_scope** — Explicit non-goal. Documented for completeness \
         so operators don't keep re-asking."
    )?;
    writeln!(w)?;

    for category in &report.categories {
        writeln!(w, "## `{}`", category.name)?;
        writeln!(w)?;
        if let Some(cat_summary) = report.summary.by_category.get(&category.name) {
            writeln!(
                w,
                "Total: {} · Supported: {} · Deferred: {} · Out of scope: {}",
                cat_summary.total,
                cat_summary.supported,
                cat_summary.deferred,
                cat_summary.out_of_scope
            )?;
            writeln!(w)?;
        }
        writeln!(w, "| Feature | Status | Test | Notes |")?;
        writeln!(w, "|---|---|---|---|")?;
        for feature in &category.features {
            let notes = feature.notes.as_deref().unwrap_or("");
            writeln!(
                w,
                "| `{}` | {} | `{}` | {} |",
                escape_md(&feature.name),
                feature.status,
                escape_md(&feature.test),
                escape_md(notes)
            )?;
        }
        writeln!(w)?;
    }
    Ok(())
}

/// Minimal Markdown-table escape: backticks survive, but pipes within a value
/// would break the table layout — replace with the Unicode broken bar so the
/// reader still sees a delimiter without misaligning the column.
fn escape_md(value: &str) -> String {
    value.replace('|', "\u{00A6}")
}
