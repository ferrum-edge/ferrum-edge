//! Producer/emitter parity for #5591. This is a source contract, not a substitute
//! for rendered-output tests: bare document values cannot be inferred by a lexer.
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

const ROOTS: &[&str] = &[
    "src/config",
    "src/modes",
    "src/cli.rs",
    "src/startup.rs",
    "src/gateway_entry.rs",
    "src/config_sources",
    "src/grpc",
    "src/plugins/waf",
    "src/notifications",
    "src/util/unknown_keys.rs",
    "src/plugins/utils/rate_limit.rs",
    "src/plugins/utils/socket_host.rs",
    "src/plugins/utils/byte_budget.rs",
    "src/plugins/utils/replay_partition.rs",
    "src/plugins/utils/response_body.rs",
];

// Exact exceptions only; adding one requires a producer/consumer justification.
// These are SQL queries, not diagnostics. `table` comes from the migration's
// fixed schema table inventory. SQL single-quote syntax must remain unchanged.
const SINGLE_QUOTE_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = '{table}' LIMIT 1",
    ),
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '{table}' LIMIT 1",
    ),
    (
        "src/config/migrations/mod.rs",
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '{table}' LIMIT 1",
    ),
];

#[derive(Debug)]
struct Token<'a> {
    text: &'a str,
    offset: usize,
    string: bool,
}

// Lex enough Rust to keep comments, escaped quotes, raw strings, char literals,
// lifetimes and nested macro arguments distinct. No line-based macro matching:
// a sanitizer in a neighbor statement must never bless an unsafe emission.
fn tokens(source: &str) -> Vec<Token<'_>> {
    let bytes = source.as_bytes();
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let start = pos;
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if source[pos..].starts_with("//") {
            pos += source[pos..].find('\n').unwrap_or(bytes.len() - pos);
            continue;
        }
        if source[pos..].starts_with("/*") {
            pos += 2;
            let mut depth = 1;
            while pos < bytes.len() && depth > 0 {
                if source[pos..].starts_with("/*") {
                    depth += 1;
                    pos += 2;
                } else if source[pos..].starts_with("*/") {
                    depth -= 1;
                    pos += 2;
                } else {
                    pos += source[pos..].chars().next().unwrap().len_utf8();
                }
            }
            assert_eq!(depth, 0, "unterminated source comment");
            continue;
        }
        // Byte/C strings share the same quote rules as ordinary strings.
        let raw_start = if source[pos..].starts_with("br") || source[pos..].starts_with("cr") {
            pos + 1
        } else {
            pos
        };
        if bytes[raw_start] == b'r' {
            let mut quote = raw_start + 1;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let end_marker = format!("\"{}", "#".repeat(quote - raw_start - 1));
                let body = quote + 1;
                let end = body + source[body..].find(&end_marker).expect("raw string end");
                pos = end + end_marker.len();
                result.push(Token {
                    text: &source[body..end],
                    offset: start,
                    string: true,
                });
                continue;
            }
        }
        let quote = if matches!(bytes[pos], b'b' | b'c') && bytes.get(pos + 1) == Some(&b'"') {
            pos + 1
        } else {
            pos
        };
        if bytes[quote] == b'"' {
            pos = quote + 1;
            let body = pos;
            while pos < bytes.len() && bytes[pos] != b'"' {
                if bytes[pos] == b'\\' {
                    pos += 1;
                }
                pos += source[pos..].chars().next().unwrap().len_utf8();
            }
            assert!(pos < bytes.len(), "unterminated source string");
            result.push(Token {
                text: &source[body..pos],
                offset: start,
                string: true,
            });
            pos += 1;
            continue;
        }
        if bytes[pos] == b'\'' {
            let mut end = pos + 1;
            if bytes.get(end) == Some(&b'\\') {
                end += 2;
                if bytes.get(end) == Some(&b'{') {
                    end += source[end..].find('}').expect("unicode character end") + 1;
                }
            } else if end < bytes.len() {
                end += source[end..].chars().next().unwrap().len_utf8();
            }
            if bytes.get(end) == Some(&b'\'') {
                pos = end + 1;
                continue;
            }
        }
        if bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_' {
            pos += 1;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
        } else {
            pos += source[pos..].chars().next().unwrap().len_utf8();
        }
        result.push(Token {
            text: &source[start..pos],
            offset: start,
            string: false,
        });
    }
    result
}

/// A format-string placeholder that interpolates an error value.
static ERROR_CAPTURE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\{(?:error|e|err|cause|message)(?::[^}]*)?\}").unwrap());

fn violations(path: &str, source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut failures = Vec::new();
    for index in 0..tokens.len().saturating_sub(2) {
        let name = &tokens[index];
        if name.string
            || !matches!(
                name.text,
                "format"
                    | "anyhow"
                    | "bail"
                    | "warn"
                    | "error"
                    | "info"
                    | "debug"
                    | "trace"
                    | "eprintln"
                    | "event"
            )
            || tokens[index + 1].text != "!"
            || !matches!(tokens[index + 2].text, "(" | "[" | "{")
        {
            continue;
        }
        let mut depth = 1;
        let mut end = index + 3;
        while end < tokens.len() && depth > 0 {
            if !tokens[end].string {
                match tokens[end].text {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => depth -= 1,
                    _ => {}
                }
            }
            end += 1;
        }
        assert_eq!(depth, 0, "unbalanced macro in {path}");
        let body = &tokens[index + 3..end - 1];
        let sanitized = body.windows(2).any(|pair| {
            !pair[0].string
                && matches!(pair[0].text, "sanitize_startup_cause" | "redact_error_text")
                && pair[1].text == "("
        });
        for literal in body.iter().filter(|token| token.string) {
            let line = source[..literal.offset]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1;
            if literal.text.contains("'{")
                && !SINGLE_QUOTE_EXCEPTIONS.contains(&(path, literal.text))
            {
                failures.push(format!(
                    "{path}:{line}: {}!: single-quoted interpolation",
                    name.text
                ));
            }
            if matches!(name.text, "warn" | "error")
                && ERROR_CAPTURE.is_match(literal.text)
                && !sanitized
            {
                failures.push(format!(
                    "{path}:{line}: {}!: unsanitized diagnostic",
                    name.text
                ));
            }
        }
    }
    failures
}

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            rust_files(&entry.unwrap().path(), files);
        }
    } else if path.extension().is_some_and(|extension| extension == "rs") {
        files.push(path.to_path_buf());
    }
}

#[test]
fn in_scope_diagnostic_producers_and_emitters_obey_the_source_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for relative in ROOTS {
        rust_files(&root.join(relative), &mut files);
    }
    files.sort();
    let mut failures = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).unwrap();
        failures.extend(violations(&relative, &source));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn diagnostic_guard_recognizes_multiline_raw_and_nested_macros() {
    for source in [
        r#"format!("invalid '{value}'")"#,
        r##"anyhow::bail!(r#"invalid '{value}'"#)"##,
        "tracing::warn!(\n field = 1,\n \"rejected: {error:#}\"\n);",
        r#"error!("{e}"); sanitize_startup_cause(e, &[]);"#,
        r#"warn!("{err}"); // sanitize_startup_cause(err, &[])"#,
        r#"warn!("{cause}", label = "sanitize_startup_cause(");"#,
        r#"error!("{message}");"#,
    ] {
        assert!(!violations("fixture.rs", source).is_empty(), "{source}");
    }
    for source in [
        r#"format!("invalid {value:?}")"#,
        r#"warn!("{}", sanitize_startup_cause(format!("{error:#}"), &[]));"#,
        r#"error!("{err}", err = redact_error_text(err, &urls));"#,
        r#"// warn!("{error}")
            let example = "format!(\"'{value}'\")";"#,
        r#"let character = '"'; let lifetime: &'a str; format!("`{field}` is invalid");"#,
    ] {
        assert!(violations("fixture.rs", source).is_empty(), "{source}");
    }
}

fn group_end(tokens: &[Token<'_>], start: usize) -> usize {
    let mut depth = 0;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        if !token.string {
            match token.text {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth -= 1;
                    if depth == 0 {
                        return index;
                    }
                }
                _ => {}
            }
        }
    }
    panic!("unbalanced source group");
}

fn compact_tokens(tokens: &[Token<'_>]) -> String {
    tokens
        .iter()
        .map(|token| {
            if token.string {
                format!("{:?}", token.text)
            } else {
                token.text.to_string()
            }
        })
        .collect()
}

fn mongo_safe_emitted_value(value: &[Token<'_>]) -> bool {
    let expression = compact_tokens(value);
    // Reviewed provenance: lease labels/modes and resource/operation names are
    // fixed at their callers; reason is a bounded enum. The rest are observed
    // counts, indexes or elapsed time, never supplied scalar configuration.
    const FIXED_OR_OBSERVED: &[&str] = &[
        "self.label",
        "self.mode",
        "label",
        "renew_label",
        "resource_type",
        "operation",
        "reason.as_str()",
        "elapsed_ms",
        "i+1",
        "failover_urls.len()",
        "result.deleted_count",
        "chunk.len()",
        "confirmed_absent.len()",
        "resource_ids.len()",
        "proxies.len()",
        "consumers.len()",
        "plugin_configs.len()",
        "upstreams.len()",
        "quarantined.len()",
    ];
    if FIXED_OR_OBSERVED.contains(&expression.as_str()) {
        return true;
    }
    if value.len() == 1 && value[0].string {
        return true;
    }
    // A scalar sanitizer must own the ENTIRE emitted expression. A neighboring
    // sanitizer, or appending an unsanitized suffix, cannot bless an argument.
    if let Some(open) = value
        .iter()
        .position(|token| !token.string && token.text == "(")
        && compact_tokens(&value[..open]) == "crate::startup::sanitize_startup_scalar"
        && group_end(value, open) == value.len() - 1
    {
        return true;
    }
    // Only these reviewed validation/typed BSON decoder outputs use the cause
    // sanitizer. It is NOT a general secret detector for driver/provider text.
    if matches!(
        expression.as_str(),
        "crate::startup::sanitize_startup_cause(message,&[])"
            | "crate::startup::sanitize_startup_cause(msg,&[])"
            | "crate::startup::sanitize_startup_cause(decode_error,&[])"
    ) {
        return true;
    }
    // TLS option branches preserve fixed absence labels. Check the Some branch
    // independently so a sanitizer elsewhere in the event does not suffice.
    for (option, fallback) in [
        ("tls_ca_cert_path", "system-roots"),
        ("tls_client_cert_path", "none"),
    ] {
        let prefix = format!("{option}.map(|value|{{");
        let suffix = format!("}}).unwrap_or_else(||{fallback:?}.to_string())");
        if let Some(inner) = expression
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(&suffix))
        {
            return mongo_safe_emitted_value(&tokens(inner));
        }
    }
    false
}

fn mongo_emission_violations(source: &str) -> Vec<String> {
    let tokens = tokens(source);
    let mut failures = Vec::new();
    for index in 0..tokens.len().saturating_sub(2) {
        if tokens[index].string
            || !matches!(
                tokens[index].text,
                "trace" | "debug" | "info" | "warn" | "error" | "event"
            )
            || tokens[index + 1].text != "!"
            || !matches!(tokens[index + 2].text, "(" | "[" | "{")
        {
            continue;
        }
        let end = group_end(&tokens, index + 2);
        let mut start = index + 3;
        let mut cursor = start;
        while cursor <= end {
            if cursor == end || (!tokens[cursor].string && tokens[cursor].text == ",") {
                let argument = &tokens[start..cursor];
                if !argument.is_empty() {
                    // Named fields keep their field name; only their value may
                    // contain supplied data. Handle both Display and Debug.
                    let mut value = if argument.len() > 2 && argument[1].text == "=" {
                        &argument[2..]
                    } else {
                        argument
                    };
                    if matches!(value[0].text, "%" | "?") {
                        value = &value[1..];
                    }
                    // Mongo events deliberately use explicit arguments. Forbid
                    // implicit captures (including numeric/boolean values) and
                    // dynamic format widths/precisions in the message literal.
                    let implicit_capture = argument.len() == 1
                        && argument[0].string
                        && argument[0].text.split('{').skip(1).any(|part| {
                            let placeholder = part.split('}').next().unwrap();
                            placeholder
                                .chars()
                                .any(|ch| ch.is_ascii_alphabetic() || ch == '_')
                        });
                    if implicit_capture || !mongo_safe_emitted_value(value) {
                        let line = source[..argument[0].offset].lines().count();
                        failures.push(format!(
                            "mongo_store.rs:{line}: unsafe emitted argument {}",
                            compact_tokens(argument)
                        ));
                    }
                }
                start = cursor + 1;
            } else if !tokens[cursor].string && matches!(tokens[cursor].text, "(" | "[" | "{") {
                cursor = group_end(&tokens, cursor);
            }
            cursor += 1;
        }
    }
    failures
}

#[test]
fn mongo_emissions_withhold_each_supplied_value_and_provider_payload() {
    // Lock/rollback/load emissions require a live database. Check every actual
    // event's arguments, not a list of expected message strings. The public
    // failover path also has captured-output coverage in startup_diagnostics.
    let source = include_str!("../../../src/config/mongo_store.rs");
    let failures = mongo_emission_violations(source);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn mongo_emission_guard_rejects_positional_structured_and_partial_sanitization() {
    for source in [
        r#"info!("namespace={:?}", namespace);"#,
        r#"warn!("rollback: {}", provider_error);"#,
        r#"error!(namespace = %namespace, error = ?provider_error, "cleanup failed");"#,
        r#"info!("threshold={}", threshold_ms);"#,
        r#"info!("replica_set={}", replica_set_configured);"#,
        r#"debug!("threshold={threshold_ms}");"#,
        r#"trace!("enabled={enabled:?}");"#,
        r#"warn!("{} {}", crate::startup::sanitize_startup_scalar(namespace), provider_error);"#,
        r#"warn!(namespace = %crate::startup::sanitize_startup_scalar(namespace), error = %provider_error, "cleanup");"#,
        r#"warn!("{}", crate::startup::sanitize_startup_scalar(namespace) + &provider_error);"#,
        r#"warn!("{}", crate::startup::sanitize_startup_cause(provider_error, &[]));"#,
        r#"warn!("{}", crate::startup::sanitize_startup_cause(format!("{provider_error}"), &[]));"#,
        r#"info!("{}", threshold_ms); crate::startup::sanitize_startup_scalar(threshold_ms);"#,
    ] {
        assert!(!mongo_emission_violations(source).is_empty(), "{source}");
    }
    for source in [
        r#"info!("namespace={}", crate::startup::sanitize_startup_scalar("'UNREGISTERED"));"#,
        r#"warn!("id={}", crate::startup::sanitize_startup_scalar("a\"UNREGISTERED"));"#,
        r#"debug!("threshold={}", crate::startup::sanitize_startup_scalar(918273641));"#,
        r#"trace!(enabled = %crate::startup::sanitize_startup_scalar(true), "TLS");"#,
        r#"error!(error = "database error (details withheld)", "cleanup failed");"#,
        r#"info!("{} resources", proxies.len());"#,
    ] {
        assert!(mongo_emission_violations(source).is_empty(), "{source}");
    }
}
