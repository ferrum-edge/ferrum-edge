//! DOC-05 parity: built-in registry, execution-order table, and protocol matrix.
//!
//! Canonical sources:
//! - names / failure policy: `BUILTIN_PLUGIN_REGISTRATIONS`
//! - classification / documented phases / matrix capability / rationale:
//!   `BUILTIN_PLUGIN_PARITY_META`
//! - live priority / default `supported_protocols()`: constructed `Plugin` trait
//!
//! Checked-in `docs/plugin_execution_order.md` tables must stay set-equal with
//! those sources (no missing, extra, duplicate, or stale name/priority/protocol
//! cells).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ferrum_edge::plugins::{
    BUILTIN_PLUGIN_PARITY_META, BUILTIN_PLUGIN_REGISTRATIONS, BuiltinPluginClassification,
    ProxyProtocol, create_plugin,
};

use super::minimal_plugin_config;

const EXECUTION_ORDER_DOC: &str = include_str!("../../../docs/plugin_execution_order.md");

#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderRow {
    index: usize,
    name: String,
    priority: u16,
    active_phases: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatrixRow {
    name: String,
    protocols: HashSet<ProxyProtocol>,
    config_only_dashes: bool,
    rationale: String,
}

fn parse_complete_order_table(doc: &str) -> Vec<OrderRow> {
    let section = doc
        .split("## Complete Execution Order")
        .nth(1)
        .expect("Complete Execution Order section");
    let table = section
        .split("### Config-only and reserved inventory rows")
        .next()
        .expect("order table before config-only subsection");
    let mut rows = Vec::new();
    let mut seen_header = false;
    for line in table.lines() {
        if line.starts_with("| # | Plugin") {
            seen_header = true;
            continue;
        }
        if !seen_header || line.starts_with("|---") {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cols: Vec<_> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert_eq!(
            cols.len(),
            4,
            "complete-order row must have 4 columns: {line}"
        );
        let index: usize = cols[0].parse().expect("order index");
        let name = cols[1].trim_matches('`').to_string();
        let priority: u16 = cols[2].parse().expect("order priority");
        rows.push(OrderRow {
            index,
            name,
            priority,
            active_phases: cols[3].to_string(),
        });
    }
    assert!(!rows.is_empty(), "complete-order table must not be empty");
    rows
}

fn parse_protocol_matrix(doc: &str) -> Vec<MatrixRow> {
    let section = doc
        .split("### Per-Plugin Protocol Matrix")
        .nth(1)
        .expect("Per-Plugin Protocol Matrix section");
    let mut rows = Vec::new();
    let mut seen_header = false;
    for line in section.lines() {
        if line.starts_with("| Plugin | Http") {
            seen_header = true;
            continue;
        }
        if !seen_header || line.starts_with("|---") || line.starts_with("|--------") {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cols: Vec<_> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert_eq!(
            cols.len(),
            7,
            "protocol-matrix row must have 7 columns: {line}"
        );
        let name = cols[0].trim_matches('`').to_string();
        let cells = &cols[1..6];
        let config_only_dashes = cells.iter().all(|c| *c == "—");
        let mut protocols = HashSet::new();
        if !config_only_dashes {
            for (cell, protocol) in cells.iter().zip([
                ProxyProtocol::Http,
                ProxyProtocol::Grpc,
                ProxyProtocol::WebSocket,
                ProxyProtocol::Tcp,
                ProxyProtocol::Udp,
            ]) {
                match *cell {
                    "✓" => {
                        protocols.insert(protocol);
                    }
                    "" => {}
                    other => panic!("unexpected protocol cell {other:?} for {name}"),
                }
            }
        }
        rows.push(MatrixRow {
            name,
            protocols,
            config_only_dashes,
            rationale: cols[6].to_string(),
        });
    }
    assert!(!rows.is_empty(), "protocol matrix must not be empty");
    rows
}

fn protocols_set(protocols: &[ProxyProtocol]) -> HashSet<ProxyProtocol> {
    protocols.iter().copied().collect()
}

fn assert_unique_names(label: &str, names: impl IntoIterator<Item = String>) {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for name in names {
        if !seen.insert(name.clone()) {
            duplicates.insert(name);
        }
    }
    assert!(
        duplicates.is_empty(),
        "{label} has duplicate plugin names: {duplicates:?}"
    );
}

#[test]
fn builtin_parity_meta_matches_registry_set() {
    let registry: BTreeSet<_> = BUILTIN_PLUGIN_REGISTRATIONS
        .iter()
        .map(|r| r.name)
        .collect();
    let meta: BTreeSet<_> = BUILTIN_PLUGIN_PARITY_META.iter().map(|m| m.name).collect();

    assert_unique_names(
        "BUILTIN_PLUGIN_REGISTRATIONS",
        BUILTIN_PLUGIN_REGISTRATIONS
            .iter()
            .map(|r| r.name.to_string()),
    );
    assert_unique_names(
        "BUILTIN_PLUGIN_PARITY_META",
        BUILTIN_PLUGIN_PARITY_META
            .iter()
            .map(|m| m.name.to_string()),
    );
    assert_eq!(
        registry,
        meta,
        "parity meta must be set-equal with BUILTIN_PLUGIN_REGISTRATIONS; missing={:?} extra={:?}",
        registry.difference(&meta).copied().collect::<Vec<_>>(),
        meta.difference(&registry).copied().collect::<Vec<_>>()
    );

    let mut priorities = BTreeMap::new();
    for entry in BUILTIN_PLUGIN_PARITY_META {
        if let Some(prev) = priorities.insert(entry.priority, entry.name) {
            panic!(
                "duplicate documented priority {} for {prev} and {}",
                entry.priority, entry.name
            );
        }
    }
}

#[tokio::test]
async fn complete_order_table_matches_parity_meta_and_runtime_priority() {
    let rows = parse_complete_order_table(EXECUTION_ORDER_DOC);
    assert_unique_names("complete-order table", rows.iter().map(|r| r.name.clone()));

    let meta_by_name: BTreeMap<_, _> = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .map(|m| (m.name, m))
        .collect();
    let doc_names: BTreeSet<_> = rows.iter().map(|r| r.name.as_str()).collect();
    let meta_names: BTreeSet<_> = meta_by_name.keys().copied().collect();
    assert_eq!(
        doc_names,
        meta_names,
        "complete-order names drifted; missing={:?} extra={:?}",
        meta_names
            .difference(&doc_names)
            .copied()
            .collect::<Vec<_>>(),
        doc_names
            .difference(&meta_names)
            .copied()
            .collect::<Vec<_>>()
    );

    for (idx, row) in rows.iter().enumerate() {
        assert_eq!(
            row.index,
            idx + 1,
            "complete-order row numbers must be dense"
        );
        let meta = meta_by_name[row.name.as_str()];
        assert_eq!(
            row.priority, meta.priority,
            "{} complete-order priority drifted from parity meta",
            row.name
        );
        assert_eq!(
            row.active_phases, meta.active_phases,
            "{} active phases drifted from parity meta",
            row.name
        );

        let config = minimal_plugin_config(&row.name);
        let plugin = create_plugin(&row.name, &config)
            .unwrap_or_else(|e| panic!("create_plugin({}) failed: {e}", row.name))
            .unwrap_or_else(|| panic!("create_plugin({}) returned None", row.name));
        assert_eq!(
            plugin.priority(),
            meta.priority,
            "{} live Plugin::priority() drifted from parity meta / docs",
            row.name
        );
    }

    let priorities: Vec<_> = rows.iter().map(|r| r.priority).collect();
    let mut sorted = priorities.clone();
    sorted.sort_unstable();
    assert_eq!(
        priorities, sorted,
        "complete-order table must be sorted by ascending priority"
    );
}

#[tokio::test]
async fn protocol_matrix_matches_parity_meta_and_runtime_protocols() {
    let rows = parse_protocol_matrix(EXECUTION_ORDER_DOC);
    assert_unique_names("protocol matrix", rows.iter().map(|r| r.name.clone()));

    let meta_by_name: BTreeMap<_, _> = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .map(|m| (m.name, m))
        .collect();
    let doc_names: BTreeSet<_> = rows.iter().map(|r| r.name.as_str()).collect();
    let meta_names: BTreeSet<_> = meta_by_name.keys().copied().collect();
    assert_eq!(
        doc_names,
        meta_names,
        "protocol-matrix names drifted; missing={:?} extra={:?}",
        meta_names
            .difference(&doc_names)
            .copied()
            .collect::<Vec<_>>(),
        doc_names
            .difference(&meta_names)
            .copied()
            .collect::<Vec<_>>()
    );

    for row in &rows {
        let meta = meta_by_name[row.name.as_str()];
        assert_eq!(
            row.rationale, meta.protocol_rationale,
            "{} protocol rationale drifted from parity meta",
            row.name
        );

        match meta.classification {
            BuiltinPluginClassification::ConfigOnly => {
                assert!(
                    row.config_only_dashes,
                    "{} is ConfigOnly and must use — in every protocol column",
                    row.name
                );
                assert!(
                    meta.matrix_protocols.is_empty(),
                    "{} ConfigOnly parity meta must use an empty matrix_protocols slice",
                    row.name
                );
                assert!(
                    row.rationale.starts_with("Config-only:"),
                    "{} ConfigOnly rationale must start with 'Config-only:'",
                    row.name
                );
            }
            BuiltinPluginClassification::Reserved => {
                assert!(
                    !row.config_only_dashes,
                    "{} is Reserved and must keep ordinary protocol checkmarks",
                    row.name
                );
                assert!(
                    row.rationale.starts_with("Reserved/"),
                    "{} Reserved rationale must start with 'Reserved/'",
                    row.name
                );
                assert_eq!(
                    row.protocols,
                    protocols_set(meta.matrix_protocols),
                    "{} matrix checkmarks drifted from parity meta",
                    row.name
                );
            }
            BuiltinPluginClassification::Public => {
                assert!(
                    !row.config_only_dashes,
                    "{} is Public and must not use config-only dashes",
                    row.name
                );
                assert_eq!(
                    row.protocols,
                    protocols_set(meta.matrix_protocols),
                    "{} matrix checkmarks drifted from parity meta",
                    row.name
                );
            }
        }

        let config = minimal_plugin_config(&row.name);
        let plugin = create_plugin(&row.name, &config)
            .unwrap_or_else(|e| panic!("create_plugin({}) failed: {e}", row.name))
            .unwrap_or_else(|| panic!("create_plugin({}) returned None", row.name));
        let live = protocols_set(plugin.supported_protocols());

        match meta.classification {
            BuiltinPluginClassification::ConfigOnly => {
                // Config-only plugins may still inherit the trait default
                // protocol list; the matrix documents non-applicability.
            }
            _ if row.name == "waf" => {
                // Documented capability envelope includes optional stream
                // inspection; minimal config attaches HTTP-family only.
                assert!(
                    live.is_subset(&row.protocols),
                    "waf live protocols {live:?} must be a subset of documented capability {:?}",
                    row.protocols
                );
                assert!(
                    live.contains(&ProxyProtocol::Http)
                        && live.contains(&ProxyProtocol::Grpc)
                        && live.contains(&ProxyProtocol::WebSocket),
                    "waf minimal config must remain HTTP-family"
                );
            }
            _ => {
                assert_eq!(
                    live, row.protocols,
                    "{} live supported_protocols() drifted from protocol matrix",
                    row.name
                );
            }
        }
    }
}

#[test]
fn special_inventory_classifications_are_documented() {
    let schema = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .find(|m| m.name == "transaction_log_schema")
        .expect("transaction_log_schema meta");
    assert_eq!(
        schema.classification,
        BuiltinPluginClassification::ConfigOnly
    );
    assert_eq!(schema.priority, 9999);

    let bpf = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .find(|m| m.name == "__mesh_bpf_metrics")
        .expect("__mesh_bpf_metrics meta");
    assert_eq!(bpf.classification, BuiltinPluginClassification::Reserved);
    assert_eq!(bpf.priority, 9365);

    assert!(
        EXECUTION_ORDER_DOC.contains("schema registration has explicit ordering\nsemantics")
            || EXECUTION_ORDER_DOC.contains("schema registration has explicit ordering semantics"),
        "docs must explain why transaction_log_schema retains ordering semantics"
    );
    assert!(
        EXECUTION_ORDER_DOC.contains("reserved, mesh-auto-injected plugin"),
        "docs must explain why __mesh_bpf_metrics is reserved/auto-injected"
    );
    assert!(
        EXECUTION_ORDER_DOC.contains("### Config-only and reserved inventory rows"),
        "docs must keep the config-only/reserved inventory subsection"
    );
}
