//! Access-log filter expression canonicalization bounds.
//!
//! Covers three-or-more same-operator chains (no recursion bomb) and the
//! post-canonical AST node ceiling after `response.code == N` expands.

use ferrum_edge::modes::mesh::access_log_filter::{
    AccessLogFilterContext, AccessLogFilterExpr, MAX_ACCESS_LOG_FILTER_AST_NODES,
    evaluate_access_log_filter_expr, parse_access_log_filter_expression,
    validate_access_log_filter_expr,
};

#[test]
fn three_term_and_flattens_without_recursion_bomb() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 400 && response.code <= 499 && response.duration >= 1000",
    )
    .expect("parses")
    .expect("filter");
    assert!(filter.expression.is_none());
    assert_eq!(filter.status_code_min, Some(400));
    assert_eq!(filter.status_code_max, Some(499));
    assert_eq!(filter.min_latency_ms, Some(1000));
}

#[test]
fn three_term_or_canonicalizes_without_recursion_bomb() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 500 || response.duration >= 1000 || response.code <= 399",
    )
    .expect("parses")
    .expect("filter");
    let expr = filter.expression.expect("uses expression tree");
    // Left-associative parser shape; boolean OR is associative so semantics
    // match any balanced tree with the same leaves.
    assert_eq!(
        expr,
        AccessLogFilterExpr::Or {
            left: Box::new(AccessLogFilterExpr::Or {
                left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
                right: Box::new(AccessLogFilterExpr::MinLatencyMs { value: 1000 }),
            }),
            right: Box::new(AccessLogFilterExpr::StatusCodeMax { value: 399 }),
        }
    );

    let match_first = AccessLogFilterContext {
        response_status_code: 503,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    let match_middle = AccessLogFilterContext {
        response_status_code: 200,
        latency_total_ms: 1500.0,
        is_terminal_failure: false,
    };
    let match_last = AccessLogFilterContext {
        response_status_code: 200,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    let match_none = AccessLogFilterContext {
        response_status_code: 404,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    assert!(evaluate_access_log_filter_expr(&expr, match_first));
    assert!(evaluate_access_log_filter_expr(&expr, match_middle));
    assert!(evaluate_access_log_filter_expr(&expr, match_last));
    assert!(!evaluate_access_log_filter_expr(&expr, match_none));
}

#[test]
fn and_still_binds_tighter_than_or_with_three_terms() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 500 || response.code >= 400 && response.code <= 499 || response.duration >= 1000",
    )
    .expect("parses")
    .expect("filter");
    let expr = filter.expression.expect("uses expression tree");
    // A || (B && C) || D  — root remains Or with an And child.
    assert!(matches!(expr, AccessLogFilterExpr::Or { .. }));
    fn contains_and(expr: &AccessLogFilterExpr) -> bool {
        match expr {
            AccessLogFilterExpr::And { .. } => true,
            AccessLogFilterExpr::Or { left, right } => contains_and(left) || contains_and(right),
            _ => false,
        }
    }
    assert!(contains_and(&expr), "&& must bind inside the || chain");
}

#[test]
fn equality_expansion_cannot_exceed_final_ast_cap() {
    // Nine `response.code == N` atoms parse as 17 nodes (9 atoms + 8 `||`),
    // under the parse-time cap, but expand to 35 final nodes
    // (9×And(min,max) + 8 Or) and must fail closed on the final bound.
    let terms: Vec<String> = (500..509)
        .map(|code| format!("response.code == {code}"))
        .collect();
    let expr = terms.join(" || ");
    let err = parse_access_log_filter_expression(&expr).expect_err("final AST cap");
    assert!(
        err.contains("maximum AST node count"),
        "expected final AST cap diagnostic, got: {err}"
    );
    assert_eq!(MAX_ACCESS_LOG_FILTER_AST_NODES, 32);
}

#[test]
fn equality_expansion_within_final_ast_cap_is_accepted() {
    // Eight equality atoms + 7 Or => 8*3 + 7 = 31 final nodes (<= 32).
    let terms: Vec<String> = (500..508)
        .map(|code| format!("response.code == {code}"))
        .collect();
    let expr = terms.join(" || ");
    let filter = parse_access_log_filter_expression(&expr)
        .expect("parses within final cap")
        .expect("filter");
    let tree = filter.expression.expect("uses expression tree");
    validate_access_log_filter_expr(&tree).expect("final tree within cap");
}

#[test]
fn pure_and_equality_chain_flattens_before_recursive_ast_cap() {
    // The canonical intermediate tree expands above 32 nodes, but this pure
    // conjunction becomes legacy flat fields and never reaches the recursive
    // evaluator, so the AST-only hot-path bound must not reject it.
    let terms = std::iter::repeat_n("response.code == 500", 9).collect::<Vec<_>>();
    let filter = parse_access_log_filter_expression(&terms.join(" && "))
        .expect("pure conjunction flattens")
        .expect("filter");
    assert!(filter.expression.is_none());
    assert_eq!(filter.status_code_min, Some(500));
    assert_eq!(filter.status_code_max, Some(500));
}

#[test]
fn invalid_identifier_diagnostics_do_not_reflect_hostile_input() {
    let hostile = "secret\u{1b}[31m-token";
    let err = parse_access_log_filter_expression(&format!("{hostile} >= 1"))
        .expect_err("unsupported identifier");
    assert!(err.contains("unsupported identifier"));
    assert!(!err.contains(hostile));

    let err = parse_access_log_filter_expression(&format!("response.code >= 500 {hostile}"))
        .expect_err("unexpected trailing input");
    assert!(err.contains("unexpected trailing input"));
    assert!(!err.contains(hostile));

    let hostile_number = "9".repeat(128);
    let err = parse_access_log_filter_expression(&format!("duration >= {hostile_number}s"))
        .expect_err("oversized integer");
    assert!(err.contains("outside supported integer range"));
    assert!(
        !err.contains(&hostile_number),
        "numeric parse diagnostics must not reflect hostile literals"
    );
}

/// Telemetry filters compile into the injected `stdout_logging` sink, which is
/// `KeepLastKnownGood`. A filter that sink would refuse must therefore be
/// refused here, at translation, rather than freezing the mesh generation.
#[test]
fn telemetry_filters_that_can_never_match_are_refused_at_translation() {
    for expression in [
        // Flat conjunction with crossed bounds.
        "response.code >= 500 && response.code <= 400",
        "response.code > 499 && response.code < 500",
        // Dead conjunction under `||` (compiles to an expression tree).
        "response.duration >= 1000 || response.code >= 500 && response.code <= 499",
    ] {
        let error = parse_access_log_filter_expression(expression)
            .expect_err("an unsatisfiable filter must be refused");
        assert!(error.contains("can never match"), "{expression}: {error}");
    }
    for expression in [
        "response.code >= 1000",
        "response.code > 999",
        "response.code == 1000 || response.duration >= 10",
    ] {
        let error = parse_access_log_filter_expression(expression)
            .expect_err("a status bound no response can carry must be refused");
        assert!(error.contains("0..=999"), "{expression}: {error}");
    }

    // The tightest satisfiable shapes stay valid.
    let exact = parse_access_log_filter_expression("response.code >= 503 && response.code <= 503")
        .expect("parses")
        .expect("filter");
    assert_eq!(exact.status_code_min, Some(503));
    assert_eq!(exact.status_code_max, Some(503));
    parse_access_log_filter_expression("response.code == 999 || response.code <= 0")
        .expect("edge status codes parse")
        .expect("filter");
}

#[test]
fn direct_expression_validation_refuses_dead_conjunctions_and_unreachable_bounds() {
    let dead = AccessLogFilterExpr::Or {
        left: Box::new(AccessLogFilterExpr::ErrorsOnly {}),
        right: Box::new(AccessLogFilterExpr::And {
            left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
            right: Box::new(AccessLogFilterExpr::StatusCodeMax { value: 400 }),
        }),
    };
    let error = validate_access_log_filter_expr(&dead).expect_err("dead conjunction");
    assert!(error.contains("can never match"), "{error}");

    let unreachable = AccessLogFilterExpr::StatusCodeMax { value: 1000 };
    let error = validate_access_log_filter_expr(&unreachable).expect_err("unreachable bound");
    assert!(error.contains("between 0 and 999"), "{error}");

    let split_across_or = AccessLogFilterExpr::And {
        left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
        right: Box::new(AccessLogFilterExpr::Or {
            left: Box::new(AccessLogFilterExpr::StatusCodeMax { value: 400 }),
            right: Box::new(AccessLogFilterExpr::ErrorsOnly {}),
        }),
    };
    validate_access_log_filter_expr(&split_across_or)
        .expect("an `or` branch may still match, so the conjunction is not provably dead");
}
