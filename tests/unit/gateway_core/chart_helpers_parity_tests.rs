//! Parity between the helpers the two Helm charts share.
//!
//! The mesh chart's strict IP / CIDR primitives are ported from the gateway
//! chart and must stay byte-comparable with it (`charts/ferrum-mesh/templates/
//! _helpers.tpl`). A fix applied to only one copy (4fb5df58f fixed mapped-IPv4
//! probe sources and bare mapped CIDRs in the mesh chart only; issue #7078)
//! must fail here, not wait for a sweep to notice.
//!
//! Every helper NAME defined in both charts is classified exactly once: either
//! it is shared and its body must be identical after the chart prefix is
//! normalized, or it is intentionally divergent with a recorded reason.

use std::collections::{BTreeMap, BTreeSet};

const GATEWAY_HELPERS: &str = include_str!("../../../charts/ferrum-gateway/templates/_helpers.tpl");
const MESH_HELPERS: &str = include_str!("../../../charts/ferrum-mesh/templates/_helpers.tpl");

/// Helpers whose bodies must be byte-identical once `ferrum-gateway.` is read
/// as `ferrum-mesh.`.
const SHARED: &[&str] = &[
    "adminAllowlistContainsIp",
    "adminAllowlistPermitsAll",
    "hexToInt",
    "ipv4Bits",
    "ipv4IntToDotted",
    "ipv4MappedToInt",
    "ipv4ToInt",
    "ipv6Bits",
    "ipv6Hextets",
    "isIpLiteral",
    "renderSecretEnv",
    "structuredDbUrl",
    "unsignedBinaryBits",
    "uriComponentEncode",
    "validAdminCidrEntry",
];

/// Helpers defined under the same name in both charts that intentionally
/// differ, with the reason.
const DIVERGENT: &[(&str, &str)] = &[
    (
        "adminHttpsPort",
        "same name, different helper: the gateway resolves a port number from \
         chart-wide `.Values.ports`; the mesh renders a container-port block \
         from a per-component resolved admin",
    ),
    (
        "image",
        "the mesh resolves the tag through `ferrum-mesh.imageTag`",
    ),
    (
        "metricsEnv",
        "the mesh reads metrics from `.Values.observability`",
    ),
    (
        "probeSource",
        "input contract only: the gateway reads the probe host from chart-wide \
         `.Values.admin` via `ferrum-gateway.probeHost`; the mesh takes an \
         already-resolved per-component host. The canonicalization below that \
         line is the same",
    ),
    (
        "renderDbUrlEnv",
        "the mesh database lives under `.Values.controlPlane.database`",
    ),
    (
        "shutdownEnv",
        "the mesh passes per-component shutdown values instead of the root context",
    ),
    (
        "sourceConfigured",
        "whitespace-only layout difference; both render `true` or nothing",
    ),
    (
        "validateOneSource",
        "the gateway also counts `secretFileMounts` sources and supports optional sources",
    ),
];

/// Extract every `define` block (from its `{{ define }}` action through the
/// matching `{{ end }}`) keyed by the helper name without the chart prefix.
/// Nesting is tracked over `if` / `range` / `with` / `block`; comment actions
/// (`{{/* ... */}}`, `{{- /* ... */ -}}`) are skipped.
fn defines(text: &str, prefix: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<(Option<String>, usize)> = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = text[cursor..].find("{{") {
        let open = cursor + offset;
        let mut inner = open + 2;
        if text[inner..].starts_with('-') {
            inner += 1;
        }
        inner += text[inner..].len() - text[inner..].trim_start().len();
        if text[inner..].starts_with("/*") {
            let comment_end = inner + text[inner..].find("*/").expect("unterminated comment");
            cursor = comment_end + text[comment_end..].find("}}").expect("unclosed comment") + 2;
            continue;
        }
        let close = inner + text[inner..].find("}}").expect("unclosed action");
        cursor = close + 2;
        let action = text[inner..close].trim_end().trim_end_matches('-').trim();
        let word = action.split_whitespace().next().unwrap_or("");
        match word {
            "define" => {
                let name = action
                    .split('"')
                    .nth(1)
                    .expect("define has a quoted name")
                    .to_string();
                stack.push((Some(name), open));
            }
            "if" | "range" | "with" | "block" => stack.push((None, open)),
            "end" => {
                let (name, start) = stack.pop().expect("unbalanced end");
                if let Some(name) = name {
                    let short = name
                        .strip_prefix(prefix)
                        .unwrap_or_else(|| panic!("{name} lacks the {prefix} prefix"));
                    out.insert(short.to_string(), text[start..cursor].to_string());
                }
            }
            _ => {}
        }
    }
    assert!(stack.is_empty(), "unbalanced template actions");
    out
}

#[test]
fn shared_chart_helpers_stay_byte_identical() {
    let gateway = defines(GATEWAY_HELPERS, "ferrum-gateway.");
    let mesh = defines(MESH_HELPERS, "ferrum-mesh.");

    let common: BTreeSet<&str> = gateway
        .keys()
        .filter(|name| mesh.contains_key(*name))
        .map(String::as_str)
        .collect();
    let classified: BTreeSet<&str> = SHARED
        .iter()
        .copied()
        .chain(DIVERGENT.iter().map(|(name, _)| *name))
        .collect();
    assert_eq!(
        SHARED.len() + DIVERGENT.len(),
        classified.len(),
        "a helper is listed twice"
    );
    assert_eq!(
        common, classified,
        "every helper defined in both charts must be listed in SHARED or DIVERGENT"
    );

    for name in SHARED {
        let normalized = gateway[*name].replace("ferrum-gateway.", "ferrum-mesh.");
        assert_eq!(
            normalized, mesh[*name],
            "{name} drifted between charts/ferrum-gateway and charts/ferrum-mesh _helpers.tpl; \
             apply the fix to both copies"
        );
    }
    for (name, reason) in DIVERGENT {
        let normalized = gateway[*name].replace("ferrum-gateway.", "ferrum-mesh.");
        assert_ne!(
            normalized, mesh[*name],
            "{name} is identical in both charts now; move it to SHARED (recorded reason: {reason})"
        );
    }
}

/// The mapped-IPv4 fixes from 4fb5df58f, pinned in the gateway copy: the probe
/// source canonicalizes an IPv4-mapped destination before the 127/8 check, and
/// the `-96` mapped-prefix adjustment applies only to an explicit prefix.
#[test]
fn gateway_chart_carries_the_mapped_ipv4_fixes() {
    let gateway = defines(GATEWAY_HELPERS, "ferrum-gateway.");
    let probe_source = &gateway["probeSource"];
    assert!(
        probe_source.contains(r#"include "ferrum-gateway.ipv4MappedToInt" $host"#),
        "probeSource must canonicalize an IPv4-mapped probe host"
    );
    assert!(
        !probe_source.contains("regexMatch"),
        "probeSource must not decide 127/8 on the destination text"
    );

    let permits_all = &gateway["adminAllowlistPermitsAll"];
    let explicit_prefix = permits_all
        .find("{{- if eq (len $parts) 2 -}}\n")
        .expect("explicit-prefix branch");
    let subtract = permits_all
        .find("{{- $prefix = sub $prefix 96 | int -}}")
        .expect("mapped -96 adjustment");
    let branch_end = explicit_prefix
        + permits_all[explicit_prefix..]
            .find("{{- $bits := include \"ferrum-gateway.ipv4Bits\"")
            .expect("bits after the prefix branch");
    assert!(
        explicit_prefix < subtract && subtract < branch_end,
        "the -96 mapped-prefix adjustment must sit inside the explicit-prefix branch"
    );
}
