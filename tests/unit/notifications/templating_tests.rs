//! Tests for the `${var}` template substitution helpers in
//! `src/notifications/templating.rs`.

use std::collections::HashMap;

use ferrum_edge::notifications::templating::{
    render_template, render_template_bounded, render_template_json_string_escaped,
    validate_template,
};

fn vars(items: &[(&str, &str)]) -> HashMap<String, String> {
    items
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn renders_known_variables() {
    let out = render_template(
        "rule=${rule_name} severity=${severity}",
        &vars(&[("rule_name", "5xx_spike"), ("severity", "high")]),
    )
    .unwrap();
    assert_eq!(out, "rule=5xx_spike severity=high");
}

#[test]
fn passes_through_unknown_variables() {
    let out = render_template(
        "rule=${rule_name} extra=${unknown}",
        &vars(&[("rule_name", "x")]),
    )
    .unwrap();
    assert_eq!(out, "rule=x extra=${unknown}");
}

#[test]
fn escapes_dollar_dollar_to_literal_dollar() {
    let out = render_template("$$rule=${name} cost=$$5", &vars(&[("name", "x")])).unwrap();
    assert_eq!(out, "$rule=x cost=$5");
}

#[test]
fn rejects_unbalanced_brace() {
    let err = render_template("good=${ok} bad=${oops", &vars(&[("ok", "x")])).unwrap_err();
    assert!(err.contains("unbalanced"), "got: {err}");
}

#[test]
fn passes_through_dollar_followed_by_non_special() {
    // `$x` (no `{`, no second `$`) is left as-is — operators commonly
    // include literal dollar signs in payloads.
    let out = render_template("price $5.00 with ${name}", &vars(&[("name", "x")])).unwrap();
    assert_eq!(out, "price $5.00 with x");
}

#[test]
fn preserves_non_ascii_text_around_variables() {
    let out = render_template("résumé ${name} Δ $$", &vars(&[("name", "東京")])).unwrap();
    assert_eq!(out, "résumé 東京 Δ $");
}

#[test]
fn json_string_rendering_escapes_substituted_values() {
    let out = render_template_json_string_escaped(
        "{\"summary\":\"${reason}\",\"plain\":\"${name}\"}",
        &vars(&[
            ("reason", "classified as [\"tls_error\"] \\ backend\nretry"),
            ("name", "東京"),
        ]),
    )
    .unwrap();
    assert_eq!(
        out,
        "{\"summary\":\"classified as [\\\"tls_error\\\"] \\\\ backend\\nretry\",\"plain\":\"東京\"}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        parsed["summary"],
        "classified as [\"tls_error\"] \\ backend\nretry"
    );
}

#[test]
fn validate_template_accepts_balanced() {
    validate_template("hello ${world} ${foo}").unwrap();
    validate_template("$$literal $$").unwrap();
    validate_template("plain text").unwrap();
}

#[test]
fn validate_template_rejects_unbalanced() {
    let err = validate_template("hello ${broken").unwrap_err();
    assert!(err.contains("unbalanced"));
}

#[test]
fn bounded_render_stops_during_substitution() {
    let out = render_template_bounded(
        "${a}${a}${a}${a}",
        &vars(&[("a", &"x".repeat(100))]),
        50,
        "...",
    )
    .unwrap();
    assert!(out.len() <= 50, "{}", out.len());
    assert!(out.ends_with("..."), "{out}");
    assert!(std::str::from_utf8(out.as_bytes()).is_ok());
}

#[test]
fn bounded_render_exact_fit_skips_marker() {
    let out = render_template_bounded("${a}", &vars(&[("a", "hello")]), 5, "...").unwrap();
    assert_eq!(out, "hello");
}

#[test]
fn bounded_render_caps_a_marker_larger_than_the_budget() {
    let out = render_template_bounded("abcdef", &HashMap::new(), 2, "[truncated]").unwrap();
    assert_eq!(out, "[t");
    assert!(out.len() <= 2);
}

#[test]
fn bounded_render_rejects_unbalanced_suffix_after_output_fills() {
    let err = render_template_bounded("x${broken", &HashMap::new(), 1, ".").unwrap_err();
    assert!(err.contains("unbalanced"), "{err}");
}
