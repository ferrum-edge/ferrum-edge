//! Telemetry access-log filter expression parsing, canonicalization, and evaluation.
//!
//! Istio `Telemetry` CRD `accessLogging.filter.expression` strings are compiled
//! at translation/cache construction time into a bounded AST. The proxy hot path
//! only evaluates the precompiled tree with short-circuit semantics.

use serde::{Deserialize, Serialize};

use super::config::AccessLogFilter;

/// Maximum accepted `filter.expression` length in bytes.
pub const MAX_ACCESS_LOG_FILTER_EXPR_LEN: usize = 4096;
/// Maximum lexer tokens while parsing an expression.
pub const MAX_ACCESS_LOG_FILTER_TOKENS: usize = 64;
/// Maximum parenthesis nesting depth.
pub const MAX_ACCESS_LOG_FILTER_NESTING: usize = 16;
/// Maximum AST nodes after canonicalization.
pub const MAX_ACCESS_LOG_FILTER_AST_NODES: usize = 32;

/// Canonical, serde-stable access-log filter expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessLogFilterExpr {
    And {
        left: Box<AccessLogFilterExpr>,
        right: Box<AccessLogFilterExpr>,
    },
    Or {
        left: Box<AccessLogFilterExpr>,
        right: Box<AccessLogFilterExpr>,
    },
    #[serde(rename = "status_code_min")]
    StatusCodeMin { value: u16 },
    #[serde(rename = "status_code_max")]
    StatusCodeMax { value: u16 },
    #[serde(rename = "min_latency_ms")]
    MinLatencyMs { value: u64 },
    #[serde(rename = "errors_only")]
    ErrorsOnly {},
}

/// HTTP transaction fields used to evaluate access-log filters.
#[derive(Debug, Clone, Copy)]
pub struct AccessLogFilterContext {
    pub response_status_code: u16,
    pub latency_total_ms: f64,
    pub is_terminal_failure: bool,
}

/// Stream transaction fields used to evaluate access-log filters.
#[derive(Debug, Clone, Copy)]
pub struct StreamAccessLogFilterContext {
    pub duration_ms: f64,
    pub has_error: bool,
}

/// Parse an Istio Telemetry `accessLogging.filter.expression` into an
/// [`AccessLogFilter`]. Returns `Ok(None)` for empty/whitespace-only input.
pub fn parse_access_log_filter_expression(expr: &str) -> Result<Option<AccessLogFilter>, String> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_ACCESS_LOG_FILTER_EXPR_LEN {
        return Err(format!(
            "Telemetry access log filter expression exceeds maximum length of \
             {MAX_ACCESS_LOG_FILTER_EXPR_LEN} bytes"
        ));
    }

    let mut parser = ExpressionParser::new(trimmed);
    let parsed = parser.parse_expression()?;
    parser.expect_end()?;
    canonicalize_access_log_filter(parsed)
}

pub fn evaluate_access_log_filter_expr(
    expr: &AccessLogFilterExpr,
    ctx: AccessLogFilterContext,
) -> bool {
    match expr {
        AccessLogFilterExpr::And { left, right } => {
            evaluate_access_log_filter_expr(left, ctx)
                && evaluate_access_log_filter_expr(right, ctx)
        }
        AccessLogFilterExpr::Or { left, right } => {
            evaluate_access_log_filter_expr(left, ctx)
                || evaluate_access_log_filter_expr(right, ctx)
        }
        AccessLogFilterExpr::StatusCodeMin { value } => ctx.response_status_code >= *value,
        AccessLogFilterExpr::StatusCodeMax { value } => ctx.response_status_code <= *value,
        AccessLogFilterExpr::MinLatencyMs { value } => ctx.latency_total_ms >= (*value as f64),
        AccessLogFilterExpr::ErrorsOnly {} => ctx.is_terminal_failure,
    }
}

pub fn evaluate_access_log_filter_expr_for_stream(
    expr: &AccessLogFilterExpr,
    ctx: StreamAccessLogFilterContext,
) -> bool {
    match expr {
        AccessLogFilterExpr::And { left, right } => {
            evaluate_access_log_filter_expr_for_stream(left, ctx)
                && evaluate_access_log_filter_expr_for_stream(right, ctx)
        }
        AccessLogFilterExpr::Or { left, right } => {
            evaluate_access_log_filter_expr_for_stream(left, ctx)
                || evaluate_access_log_filter_expr_for_stream(right, ctx)
        }
        AccessLogFilterExpr::StatusCodeMin { .. } | AccessLogFilterExpr::StatusCodeMax { .. } => {
            false
        }
        AccessLogFilterExpr::MinLatencyMs { value } => ctx.duration_ms >= (*value as f64),
        AccessLogFilterExpr::ErrorsOnly {} => ctx.has_error,
    }
}

/// Validate a serialized expression tree at the plugin/config boundary.
///
/// Istio expressions already cross the bounded parser above, but operators can
/// configure `stdout_logging.filter.expression` directly. Keep that path under
/// the same node ceiling so the recursive hot-path evaluator has a proven
/// bound regardless of where the configuration originated.
pub fn validate_access_log_filter_expr(expr: &AccessLogFilterExpr) -> Result<(), String> {
    let mut pending = vec![expr];
    let mut node_count = 0usize;
    while let Some(node) = pending.pop() {
        node_count += 1;
        if node_count > MAX_ACCESS_LOG_FILTER_AST_NODES {
            return Err(format!(
                "access log filter expression exceeds maximum AST node count of \
                 {MAX_ACCESS_LOG_FILTER_AST_NODES}"
            ));
        }
        match node {
            AccessLogFilterExpr::And { left, right } | AccessLogFilterExpr::Or { left, right } => {
                pending.push(right);
                pending.push(left);
            }
            AccessLogFilterExpr::StatusCodeMin { .. }
            | AccessLogFilterExpr::StatusCodeMax { .. }
            | AccessLogFilterExpr::MinLatencyMs { .. }
            | AccessLogFilterExpr::ErrorsOnly {} => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedExpr {
    And(Box<ParsedExpr>, Box<ParsedExpr>),
    Or(Box<ParsedExpr>, Box<ParsedExpr>),
    Atom(ComparisonAtom),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComparisonAtom {
    StatusCode(Comparison),
    Duration(DurationComparison),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Gte(i64),
    Gt(i64),
    Lte(i64),
    Lt(i64),
    Eq(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurationComparison {
    Gte(i64),
    Gt(i64),
}

struct ExpressionParser<'a> {
    input: &'a str,
    pos: usize,
    token_count: usize,
    paren_depth: usize,
    node_count: usize,
}

impl<'a> ExpressionParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            token_count: 0,
            paren_depth: 0,
            node_count: 0,
        }
    }

    fn parse_expression(&mut self) -> Result<ParsedExpr, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<ParsedExpr, String> {
        let mut left = self.parse_and()?;
        while self.consume_token("||")? {
            let right = self.parse_and()?;
            left = ParsedExpr::Or(Box::new(left), Box::new(right));
            self.bump_node_count()?;
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<ParsedExpr, String> {
        let mut left = self.parse_primary()?;
        while self.consume_token("&&")? {
            let right = self.parse_primary()?;
            left = ParsedExpr::And(Box::new(left), Box::new(right));
            self.bump_node_count()?;
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<ParsedExpr, String> {
        self.skip_whitespace();
        if self.consume_token("(")? {
            self.paren_depth += 1;
            if self.paren_depth > MAX_ACCESS_LOG_FILTER_NESTING {
                return Err(format!(
                    "Telemetry access log filter expression exceeds maximum nesting depth of \
                     {MAX_ACCESS_LOG_FILTER_NESTING}"
                ));
            }
            let expr = self.parse_expression()?;
            self.skip_whitespace();
            if !self.consume_token(")")? {
                return Err("Telemetry access log filter expression has unclosed '('".to_string());
            }
            self.paren_depth -= 1;
            return Ok(expr);
        }

        let atom = self.parse_atom()?;
        self.bump_node_count()?;
        Ok(ParsedExpr::Atom(atom))
    }

    fn parse_atom(&mut self) -> Result<ComparisonAtom, String> {
        self.skip_whitespace();
        let start = self.pos;
        if self.starts_with_identifier("response.code")
            || self.starts_with_identifier("response.status")
        {
            self.pos += if self.starts_with_identifier("response.code") {
                "response.code".len()
            } else {
                "response.status".len()
            };
            self.skip_whitespace();
            let comparison =
                self.parse_numeric_comparison("Telemetry access log response.code filter")?;
            return Ok(ComparisonAtom::StatusCode(comparison));
        }
        let duration_identifier_len = if self.starts_with_identifier("response.duration") {
            Some("response.duration".len())
        } else if self.starts_with_identifier("duration") {
            Some("duration".len())
        } else {
            None
        };
        if let Some(identifier_len) = duration_identifier_len {
            self.pos += identifier_len;
            self.skip_whitespace();
            let comparison =
                self.parse_duration_comparison("Telemetry access log response.duration filter")?;
            return Ok(ComparisonAtom::Duration(comparison));
        }

        if self.remaining_identifier_prefix(start).is_empty() {
            return Err(
                "Telemetry access log filter expression is missing a comparison atom".to_string(),
            );
        }
        // Do not reflect an operator-controlled identifier into diagnostics:
        // this error can cross logging/admin boundaries and the fragment may
        // contain terminal controls or credential-like text.
        Err("Telemetry access log filter expression has unsupported identifier".to_string())
    }

    fn parse_numeric_comparison(&mut self, field: &str) -> Result<Comparison, String> {
        let op = self.parse_comparison_operator(field)?;
        self.skip_whitespace();
        let value = self.parse_signed_integer(field)?;
        Ok(match op {
            ">=" => Comparison::Gte(value),
            ">" => Comparison::Gt(value),
            "<=" => Comparison::Lte(value),
            "<" => Comparison::Lt(value),
            "==" => Comparison::Eq(value),
            _ => unreachable!("parse_comparison_operator only returns supported ops"),
        })
    }

    fn parse_duration_comparison(&mut self, field: &str) -> Result<DurationComparison, String> {
        let op = self.parse_comparison_operator(field)?;
        match op {
            ">=" => {}
            ">" => {}
            other => {
                // Field labels end with "filter"; do not append another "filter"
                // before "filters" or the diagnostic becomes "...filter filters...".
                return Err(format!(
                    "Telemetry access log response.duration filters only support '>' and '>=' (got '{other}')"
                ));
            }
        }
        self.skip_whitespace();
        let value = self.parse_signed_integer(field)?;
        let multiplier = self.parse_duration_unit_multiplier()?;
        let value = value.checked_mul(multiplier).ok_or_else(|| {
            "Telemetry access log duration filter value overflows milliseconds".to_string()
        })?;
        Ok(match op {
            ">=" => DurationComparison::Gte(value),
            ">" => DurationComparison::Gt(value),
            _ => unreachable!(),
        })
    }

    fn parse_comparison_operator(&mut self, field: &str) -> Result<&'static str, String> {
        self.skip_whitespace();
        for op in [">=", "<=", "==", ">", "<"] {
            if self.input[self.pos..].starts_with(op) {
                // Reject malformed runs like `>>`, `<<`, `===` at the operator
                // boundary instead of greedily accepting the first valid prefix
                // and then failing later as an empty/non-number value.
                let after = self.pos + op.len();
                if self
                    .input
                    .get(after..)
                    .and_then(|rest| rest.chars().next())
                    .is_some_and(|ch| matches!(ch, '>' | '<' | '='))
                {
                    return Err(format!("{field} must use a numeric comparison"));
                }
                self.pos = after;
                self.bump_token_count()?;
                return Ok(op);
            }
        }
        Err(format!("{field} must use a numeric comparison"))
    }

    fn parse_signed_integer(&mut self, field: &str) -> Result<i64, String> {
        self.skip_whitespace();
        let start = self.pos;
        if self.peek_char() == Some('-') {
            self.pos += 1;
        }
        if !self.peek_is_ascii_digit() {
            let fragment = self.input.get(start..self.pos).unwrap_or("");
            return Err(format!(
                "{field} comparison value '{fragment}' is not a number"
            ));
        }
        while self.peek_is_ascii_digit() {
            self.pos += 1;
        }
        let raw = &self.input[start..self.pos];
        raw.parse::<i64>()
            .map_err(|_| format!("{field} comparison value is outside supported integer range"))
    }

    fn parse_duration_unit_multiplier(&mut self) -> Result<i64, String> {
        for (unit, multiplier) in [("ms", 1), ("s", 1_000)] {
            if !self.input[self.pos..].starts_with(unit) {
                continue;
            }
            let after = self.pos + unit.len();
            if self
                .input
                .get(after..)
                .and_then(|rest| rest.chars().next())
                .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                continue;
            }
            self.pos = after;
            self.bump_token_count()?;
            return Ok(multiplier);
        }
        Ok(1)
    }

    fn consume_token(&mut self, token: &str) -> Result<bool, String> {
        self.skip_whitespace();
        if self.input[self.pos..].starts_with(token) {
            self.pos += token.len();
            self.bump_token_count()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn bump_token_count(&mut self) -> Result<(), String> {
        self.token_count += 1;
        if self.token_count > MAX_ACCESS_LOG_FILTER_TOKENS {
            return Err(format!(
                "Telemetry access log filter expression exceeds maximum token count of \
                 {MAX_ACCESS_LOG_FILTER_TOKENS}"
            ));
        }
        Ok(())
    }

    fn bump_node_count(&mut self) -> Result<(), String> {
        self.node_count += 1;
        if self.node_count > MAX_ACCESS_LOG_FILTER_AST_NODES {
            return Err(format!(
                "Telemetry access log filter expression exceeds maximum AST node count of \
                 {MAX_ACCESS_LOG_FILTER_AST_NODES}"
            ));
        }
        Ok(())
    }

    fn expect_end(&mut self) -> Result<(), String> {
        self.skip_whitespace();
        if self.pos == self.input.len() {
            return Ok(());
        }
        if self.input[self.pos..].starts_with(")") {
            return Err("Telemetry access log filter expression has unmatched ')'".to_string());
        }
        // As above, keep diagnostics field-oriented without echoing the
        // operator-controlled trailing fragment.
        Err("Telemetry access log filter expression has unexpected trailing input".to_string())
    }

    fn starts_with_identifier(&self, ident: &str) -> bool {
        self.input[self.pos..].starts_with(ident)
            && !self
                .input
                .get(self.pos + ident.len()..)
                .and_then(|rest| rest.chars().next())
                .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    }

    fn remaining_identifier_prefix(&self, start: usize) -> String {
        let mut end = start;
        while let Some(ch) = self.input[end..].chars().next() {
            if ch.is_whitespace() || matches!(ch, '(' | ')' | '&' | '|' | '=' | '<' | '>') {
                break;
            }
            end += ch.len_utf8();
        }
        self.input[start..end].trim().to_string()
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn peek_is_ascii_digit(&self) -> bool {
        self.peek_char().is_some_and(|ch| ch.is_ascii_digit())
    }
}

fn canonicalize_access_log_filter(parsed: ParsedExpr) -> Result<Option<AccessLogFilter>, String> {
    let canonical = canonicalize_parsed_expr(parsed)?;
    if let Some(flat) = flatten_and_only(&canonical)? {
        return Ok(Some(flat));
    }
    // Parser node accounting charges one node per equality atom, but
    // `response.code == N` expands into And(min, max) (three final nodes).
    // Re-validate any tree that will reach the recursive hot-path evaluator.
    // Pure conjunctions above were reduced to non-recursive legacy fields.
    validate_access_log_filter_expr(&canonical)?;
    Ok(Some(AccessLogFilter {
        status_code_min: None,
        status_code_max: None,
        min_latency_ms: None,
        errors_only: false,
        expression: Some(canonical),
    }))
}

fn canonicalize_parsed_expr(parsed: ParsedExpr) -> Result<AccessLogFilterExpr, String> {
    match parsed {
        ParsedExpr::And(left, right) => {
            let left = canonicalize_parsed_expr(*left)?;
            let right = canonicalize_parsed_expr(*right)?;
            // Preserve the parser's left-associative shape. Same-operator
            // reassociation must not recurse into an identical tree or
            // three-or-more term chains stack-overflow during translation.
            Ok(AccessLogFilterExpr::And {
                left: Box::new(left),
                right: Box::new(right),
            })
        }
        ParsedExpr::Or(left, right) => {
            let left = canonicalize_parsed_expr(*left)?;
            let right = canonicalize_parsed_expr(*right)?;
            Ok(AccessLogFilterExpr::Or {
                left: Box::new(left),
                right: Box::new(right),
            })
        }
        ParsedExpr::Atom(atom) => atom_to_expr(atom),
    }
}

fn flatten_and_only(expr: &AccessLogFilterExpr) -> Result<Option<AccessLogFilter>, String> {
    let mut atoms = Vec::new();
    if collect_and_atoms(expr, &mut atoms).is_none() {
        return Ok(None);
    }
    let mut filter = AccessLogFilter {
        status_code_min: None,
        status_code_max: None,
        min_latency_ms: None,
        errors_only: false,
        expression: None,
    };
    for atom in atoms {
        apply_atom_to_filter(&mut filter, atom)?;
    }
    Ok(Some(filter))
}

fn collect_and_atoms<'a>(
    expr: &'a AccessLogFilterExpr,
    out: &mut Vec<&'a AccessLogFilterExpr>,
) -> Option<()> {
    match expr {
        AccessLogFilterExpr::And { left, right } => {
            collect_and_atoms(left, out)?;
            collect_and_atoms(right, out)?;
            Some(())
        }
        AccessLogFilterExpr::Or { .. } => None,
        leaf => {
            out.push(leaf);
            Some(())
        }
    }
}

fn apply_atom_to_filter(
    filter: &mut AccessLogFilter,
    atom: &AccessLogFilterExpr,
) -> Result<(), String> {
    match atom {
        AccessLogFilterExpr::StatusCodeMin { value } => {
            merge_status_code_min(&mut filter.status_code_min, i64::from(*value))?;
        }
        AccessLogFilterExpr::StatusCodeMax { value } => {
            merge_status_code_max(&mut filter.status_code_max, i64::from(*value))?;
        }
        AccessLogFilterExpr::MinLatencyMs { value } => {
            merge_min_latency_ms(
                &mut filter.min_latency_ms,
                i64::try_from(*value).map_err(|_| {
                    "Telemetry access log duration filter value must be non-negative".to_string()
                })?,
            )?;
        }
        AccessLogFilterExpr::ErrorsOnly {} => filter.errors_only = true,
        AccessLogFilterExpr::And { .. } | AccessLogFilterExpr::Or { .. } => {
            return Err(
                "internal access log filter canonicalization produced an unexpected boolean node"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn atom_to_expr(atom: ComparisonAtom) -> Result<AccessLogFilterExpr, String> {
    match atom {
        ComparisonAtom::StatusCode(comparison) => status_comparison_to_expr(comparison),
        ComparisonAtom::Duration(comparison) => duration_comparison_to_expr(comparison),
    }
}

fn status_comparison_to_expr(comparison: Comparison) -> Result<AccessLogFilterExpr, String> {
    match comparison {
        Comparison::Gte(n) => Ok(AccessLogFilterExpr::StatusCodeMin {
            value: status_code_value(n)?,
        }),
        Comparison::Gt(n) => Ok(AccessLogFilterExpr::StatusCodeMin {
            value: status_code_value(comparison_increment(n)?)?,
        }),
        Comparison::Lte(n) => Ok(AccessLogFilterExpr::StatusCodeMax {
            value: status_code_value(n)?,
        }),
        Comparison::Lt(n) => Ok(AccessLogFilterExpr::StatusCodeMax {
            value: status_code_value(comparison_decrement(n)?)?,
        }),
        Comparison::Eq(n) => {
            let value = status_code_value(n)?;
            Ok(AccessLogFilterExpr::And {
                left: Box::new(AccessLogFilterExpr::StatusCodeMin { value }),
                right: Box::new(AccessLogFilterExpr::StatusCodeMax { value }),
            })
        }
    }
}

fn duration_comparison_to_expr(
    comparison: DurationComparison,
) -> Result<AccessLogFilterExpr, String> {
    match comparison {
        DurationComparison::Gte(n) => Ok(AccessLogFilterExpr::MinLatencyMs {
            value: duration_value(n)?,
        }),
        DurationComparison::Gt(n) => Ok(AccessLogFilterExpr::MinLatencyMs {
            value: duration_value(comparison_increment(n)?)?,
        }),
    }
}

fn merge_status_code_min(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
}

fn merge_status_code_max(current: &mut Option<u16>, value: i64) -> Result<(), String> {
    let value = status_code_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.min(value)));
    Ok(())
}

fn merge_min_latency_ms(current: &mut Option<u64>, value: i64) -> Result<(), String> {
    let value = duration_value(value)?;
    *current = Some(current.map_or(value, |existing| existing.max(value)));
    Ok(())
}

fn status_code_value(value: i64) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| {
        format!("Telemetry access log response code filter value {value} is outside 0..=65535")
    })
}

fn duration_value(value: i64) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| {
        format!("Telemetry access log duration filter value {value} must be non-negative")
    })
}

fn comparison_increment(value: i64) -> Result<i64, String> {
    value
        .checked_add(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} overflows"))
}

fn comparison_decrement(value: i64) -> Result<i64, String> {
    value
        .checked_sub(1)
        .ok_or_else(|| format!("Telemetry access log comparison value {value} underflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_precedence_over_or() {
        let filter = parse_access_log_filter_expression(
            "response.code >= 400 && response.code <= 499 || response.duration >= 1000",
        )
        .expect("parses")
        .expect("filter");
        let expr = filter.expression.expect("uses expression tree");
        assert!(matches!(expr, AccessLogFilterExpr::Or { .. }));
    }

    #[test]
    fn parentheses_override_precedence() {
        // Without parens, `&&` binds tighter than `||` so the root would be `Or`.
        // Parentheses force `(A || B) && C`, whose canonical root is `And`.
        let filter = parse_access_log_filter_expression(
            "(response.code >= 500 || response.duration >= 1000) && response.code <= 599",
        )
        .expect("parses")
        .expect("filter");
        let expr = filter.expression.expect("uses expression tree");
        assert!(
            matches!(
                expr,
                AccessLogFilterExpr::And {
                    left,
                    right: _
                } if matches!(left.as_ref(), AccessLogFilterExpr::Or { .. })
            ),
            "parentheses must force And(Or(...), ...) rather than default Or precedence"
        );
    }

    #[test]
    fn errors_or_slow_canonicalizes_to_or_tree() {
        let filter = parse_access_log_filter_expression("response.code >= 500 || duration > 1s")
            .expect("parses")
            .expect("filter");
        let expr = filter.expression.expect("uses expression tree");
        assert_eq!(
            expr,
            AccessLogFilterExpr::Or {
                left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
                right: Box::new(AccessLogFilterExpr::MinLatencyMs { value: 1001 }),
            }
        );
    }

    #[test]
    fn duration_units_convert_to_milliseconds_and_overflow_fails_closed() {
        let filter = parse_access_log_filter_expression("response.duration >= 1500ms")
            .expect("millisecond suffix parses")
            .expect("filter");
        assert_eq!(filter.min_latency_ms, Some(1500));

        let error = parse_access_log_filter_expression("duration >= 9223372036854776s")
            .expect_err("seconds-to-milliseconds overflow must fail closed");
        assert!(error.contains("overflows milliseconds"), "{error}");
    }

    #[test]
    fn pure_and_stays_flat() {
        let filter =
            parse_access_log_filter_expression("response.code >= 500 && response.duration >= 1000")
                .expect("parses")
                .expect("filter");
        assert!(filter.expression.is_none());
        assert_eq!(filter.status_code_min, Some(500));
        assert_eq!(filter.min_latency_ms, Some(1000));
    }

    #[test]
    fn short_circuit_or_evaluation() {
        let expr = AccessLogFilterExpr::Or {
            left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
            right: Box::new(AccessLogFilterExpr::MinLatencyMs { value: 10_000 }),
        };
        let ctx = AccessLogFilterContext {
            response_status_code: 503,
            latency_total_ms: 1.0,
            is_terminal_failure: false,
        };
        assert!(evaluate_access_log_filter_expr(&expr, ctx));
    }

    #[test]
    fn rejects_deeply_nested_bomb() {
        let mut expr = "response.code >= 500".to_string();
        for _ in 0..=MAX_ACCESS_LOG_FILTER_NESTING {
            expr = format!("({expr})");
        }
        let err = parse_access_log_filter_expression(&expr).expect_err("nesting limit");
        assert!(err.contains("maximum nesting depth"));
    }
}
