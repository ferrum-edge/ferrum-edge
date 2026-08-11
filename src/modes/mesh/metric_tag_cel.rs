//! Bounded CEL subset for Istio Telemetry metric `tagOverrides` UPSERT values.
//!
//! Expressions are compiled at Telemetry translation / `workload_metrics`
//! construction (reload) time into a serde-stable AST. The Prometheus mesh
//! metric path evaluates the precompiled tree against attributes that are
//! authoritative at the `log` / stream-disconnect metric phase — never by
//! re-parsing CEL on the request hot path.
//!
//! # Supported attribute environment
//!
//! Attributes must be observable from the finalized mesh metric key and the
//! metadata / summary fields stamped before metric emission:
//!
//! | Attribute | Type | Authoritative source |
//! |---|---|---|
//! | `source.workload` / `source.namespace` / `source.principal` / `source.app` / `source.service` | string | `MeshRequestKey` peer labels |
//! | `destination.workload` / `destination.namespace` / `destination.principal` / `destination.app` / `destination.service` | string | `MeshRequestKey` peer labels |
//! | `request.protocol` | string | `MeshRequestKey.request_protocol` |
//! | `response.flags` | string | `MeshRequestKey.response_flags` |
//! | `connection.security_policy` | string | `MeshRequestKey.connection_security_policy` |
//! | `request.method` | string | HTTP/gRPC summary `http_method` / internal metric CEL stamp |
//! | `request.host` | string | internal metric CEL request-authority stamp |
//! | `response.code` | int | HTTP/gRPC response status |
//! | `destination.port` | int | internal metric CEL stamp (same resolution as mesh authz) |
//!
//! `has(<string attribute>)` tests presence in the evaluation context. Mesh-key
//! string attributes default to the sentinel `unknown` and are therefore always
//! present — `has(source.workload)` does not test attribution resolution. Only
//! `request.method` and `request.host` can be absent.
//!
//! HTTP-only attributes (`request.method`, `request.host`, `response.code`) are
//! rejected when the override targets a TCP metric family or `ALL_METRICS`
//! (TCP families cannot authoritatively observe them). Headers, body bytes,
//! credentials, client IPs, and request paths are intentionally unsupported
//! (credential exposure and/or unbounded cardinality).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum accepted UPSERT expression length in UTF-8 bytes.
pub const MAX_METRIC_TAG_CEL_EXPR_LEN: usize = 512;
/// Maximum lexer tokens while parsing an expression.
pub const MAX_METRIC_TAG_CEL_TOKENS: usize = 32;
/// Maximum parenthesis / ternary nesting depth.
pub const MAX_METRIC_TAG_CEL_NESTING: usize = 8;
/// Maximum AST nodes after compilation.
pub const MAX_METRIC_TAG_CEL_AST_NODES: usize = 24;
/// Maximum evaluated / sanitized label value bytes (matches workload_metrics).
pub const MAX_METRIC_TAG_CEL_OUTPUT_BYTES: usize = 256;

/// Internal-only metadata stamps consumed when a mesh metric key is finalized.
/// The reserved `mesh.metrics.*` prefix keeps these request-derived values out
/// of external transaction logs and OpenTelemetry span attributes.
pub(crate) const METRIC_TAG_CEL_REQUEST_HOST_METADATA: &str = "mesh.metrics.cel.request_host";
pub(crate) const METRIC_TAG_CEL_REQUEST_METHOD_METADATA: &str = "mesh.metrics.cel.request_method";
pub(crate) const METRIC_TAG_CEL_DESTINATION_PORT_METADATA: &str =
    "mesh.metrics.cel.destination_port";

/// Serde-stable compiled UPSERT expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MetricTagCelExpr {
    Literal {
        value: String,
    },
    Attribute {
        name: MetricTagCelAttr,
    },
    /// `string(<int attribute>)`.
    StringOfInt {
        attribute: MetricTagCelAttr,
    },
    /// `has(<string attribute>) ? <then> : <else>`.
    HasThenElse {
        attribute: MetricTagCelAttr,
        then_expr: Box<MetricTagCelExpr>,
        else_expr: Box<MetricTagCelExpr>,
    },
}

/// Closed allow-list of CEL attributes for metric tag UPSERT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricTagCelAttr {
    SourceWorkload,
    SourceNamespace,
    SourcePrincipal,
    SourceApp,
    SourceService,
    DestinationWorkload,
    DestinationNamespace,
    DestinationPrincipal,
    DestinationApp,
    DestinationService,
    RequestProtocol,
    ResponseFlags,
    ConnectionSecurityPolicy,
    RequestMethod,
    RequestHost,
    ResponseCode,
    DestinationPort,
}

impl MetricTagCelAttr {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "source.workload" | "source_workload" => Some(Self::SourceWorkload),
            "source.namespace" | "source_namespace" | "source_workload_namespace" => {
                Some(Self::SourceNamespace)
            }
            "source.principal" | "source_principal" => Some(Self::SourcePrincipal),
            "source.app" | "source_app" => Some(Self::SourceApp),
            "source.service" | "source_service" | "source.canonical_service" => {
                Some(Self::SourceService)
            }
            "destination.workload" | "destination_workload" => Some(Self::DestinationWorkload),
            "destination.namespace"
            | "destination_namespace"
            | "destination_workload_namespace" => Some(Self::DestinationNamespace),
            "destination.principal" | "destination_principal" => Some(Self::DestinationPrincipal),
            "destination.app" | "destination_app" => Some(Self::DestinationApp),
            "destination.service" | "destination_service" | "destination.canonical_service" => {
                Some(Self::DestinationService)
            }
            "request.protocol" | "request_protocol" => Some(Self::RequestProtocol),
            "response.flags" | "response_flags" => Some(Self::ResponseFlags),
            "connection.security_policy" | "connection_security_policy" => {
                Some(Self::ConnectionSecurityPolicy)
            }
            "request.method" | "request_method" => Some(Self::RequestMethod),
            "request.host" | "request_host" => Some(Self::RequestHost),
            "response.code" | "response_code" | "response.status" => Some(Self::ResponseCode),
            "destination.port" | "destination_port" => Some(Self::DestinationPort),
            _ => None,
        }
    }

    pub const fn is_http_only(self) -> bool {
        matches!(
            self,
            Self::RequestMethod | Self::RequestHost | Self::ResponseCode
        )
    }

    pub const fn is_int(self) -> bool {
        matches!(self, Self::ResponseCode | Self::DestinationPort)
    }

    /// Compact plan attribute id (stable; do not reorder).
    pub const fn plan_id(self) -> u8 {
        match self {
            Self::SourceWorkload => 0,
            Self::SourceNamespace => 1,
            Self::SourcePrincipal => 2,
            Self::SourceApp => 3,
            Self::SourceService => 4,
            Self::DestinationWorkload => 5,
            Self::DestinationNamespace => 6,
            Self::DestinationPrincipal => 7,
            Self::DestinationApp => 8,
            Self::DestinationService => 9,
            Self::RequestProtocol => 10,
            Self::ResponseFlags => 11,
            Self::ConnectionSecurityPolicy => 12,
            Self::RequestMethod => 13,
            Self::RequestHost => 14,
            Self::ResponseCode => 15,
            Self::DestinationPort => 16,
        }
    }

    pub fn from_plan_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::SourceWorkload),
            1 => Some(Self::SourceNamespace),
            2 => Some(Self::SourcePrincipal),
            3 => Some(Self::SourceApp),
            4 => Some(Self::SourceService),
            5 => Some(Self::DestinationWorkload),
            6 => Some(Self::DestinationNamespace),
            7 => Some(Self::DestinationPrincipal),
            8 => Some(Self::DestinationApp),
            9 => Some(Self::DestinationService),
            10 => Some(Self::RequestProtocol),
            11 => Some(Self::ResponseFlags),
            12 => Some(Self::ConnectionSecurityPolicy),
            13 => Some(Self::RequestMethod),
            14 => Some(Self::RequestHost),
            15 => Some(Self::ResponseCode),
            16 => Some(Self::DestinationPort),
            _ => None,
        }
    }
}

/// Immutable hot-path stamp requirements derived from compiled CEL at
/// construction / reload. Request/stream hooks read these flags only — they
/// never re-parse expressions or take locks to decide which attributes to
/// materialize into metadata.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MetricTagCelStampNeeds {
    pub request_host: bool,
    pub request_method: bool,
    pub destination_port: bool,
}

impl MetricTagCelStampNeeds {
    const REQUEST_HOST_BIT: u8 = 1;
    const REQUEST_METHOD_BIT: u8 = 1 << 1;
    const DESTINATION_PORT_BIT: u8 = 1 << 2;

    pub fn merge(&mut self, other: Self) {
        self.request_host |= other.request_host;
        self.request_method |= other.request_method;
        self.destination_port |= other.destination_port;
    }

    /// Compact, construction-time marker embedded in one metric family's
    /// override plan. Keeping the marker per family lets several effective
    /// `workload_metrics` instances compose without a later instance clearing
    /// an attribute still required by an earlier surviving family plan.
    pub(crate) const fn marker(self) -> &'static str {
        match self.bitmask() {
            0 => "0",
            1 => "1",
            2 => "2",
            3 => "3",
            4 => "4",
            5 => "5",
            6 => "6",
            7 => "7",
            _ => "7",
        }
    }

    pub(crate) fn from_marker(marker: &str) -> Option<Self> {
        let bits = match marker {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            "5" => 5,
            "6" => 6,
            "7" => 7,
            _ => return None,
        };
        Some(Self {
            request_host: bits & Self::REQUEST_HOST_BIT != 0,
            request_method: bits & Self::REQUEST_METHOD_BIT != 0,
            destination_port: bits & Self::DESTINATION_PORT_BIT != 0,
        })
    }

    pub(crate) const fn all() -> Self {
        Self {
            request_host: true,
            request_method: true,
            destination_port: true,
        }
    }

    const fn bitmask(self) -> u8 {
        let mut bits = 0;
        if self.request_host {
            bits |= Self::REQUEST_HOST_BIT;
        }
        if self.request_method {
            bits |= Self::REQUEST_METHOD_BIT;
        }
        if self.destination_port {
            bits |= Self::DESTINATION_PORT_BIT;
        }
        bits
    }
}

/// Split the self-contained compact family plan into its CEL input marker and
/// operation body. A malformed marker invalidates the whole plan; callers that
/// decide what to stamp may conservatively fall back to [`MetricTagCelStampNeeds::all`],
/// while metric evaluation applies no partial operations.
pub(crate) fn split_metric_tag_cel_plan(plan: &str) -> Option<(MetricTagCelStampNeeds, &str)> {
    let plan = plan.strip_prefix('m')?;
    let (marker, operations) = plan.split_once(';')?;
    Some((MetricTagCelStampNeeds::from_marker(marker)?, operations))
}

impl MetricTagCelExpr {
    /// Attributes that must be stamped into request/stream metadata before
    /// metric emission for this expression to observe them.
    pub fn stamp_needs(&self) -> MetricTagCelStampNeeds {
        let mut needs = MetricTagCelStampNeeds::default();
        self.accumulate_stamp_needs(&mut needs);
        needs
    }

    fn accumulate_stamp_needs(&self, needs: &mut MetricTagCelStampNeeds) {
        match self {
            Self::Literal { .. } => {}
            Self::Attribute { name } => accumulate_attr_stamp_need(*name, needs),
            Self::StringOfInt { attribute } => accumulate_attr_stamp_need(*attribute, needs),
            Self::HasThenElse {
                attribute,
                then_expr,
                else_expr,
            } => {
                accumulate_attr_stamp_need(*attribute, needs);
                then_expr.accumulate_stamp_needs(needs);
                else_expr.accumulate_stamp_needs(needs);
            }
        }
    }
}

fn accumulate_attr_stamp_need(attr: MetricTagCelAttr, needs: &mut MetricTagCelStampNeeds) {
    match attr {
        MetricTagCelAttr::RequestHost => needs.request_host = true,
        MetricTagCelAttr::RequestMethod => needs.request_method = true,
        MetricTagCelAttr::DestinationPort => needs.destination_port = true,
        // Peer / protocol / flags / security_policy / response.code come from
        // the finalized mesh key or summary at emission — not stamped metadata.
        _ => {}
    }
}

/// Evaluation inputs available when mesh metric labels are finalized.
#[derive(Debug, Clone, Copy)]
pub struct MetricTagCelContext<'a> {
    pub source_workload: &'a str,
    pub source_namespace: &'a str,
    pub source_principal: &'a str,
    pub source_app: &'a str,
    pub source_service: &'a str,
    pub destination_workload: &'a str,
    pub destination_namespace: &'a str,
    pub destination_principal: &'a str,
    pub destination_app: &'a str,
    pub destination_service: &'a str,
    pub request_protocol: &'a str,
    pub response_flags: &'a str,
    pub connection_security_policy: &'a str,
    pub request_method: Option<&'a str>,
    pub request_host: Option<&'a str>,
    pub response_code: Option<u16>,
    pub destination_port: Option<u16>,
}

impl<'a> MetricTagCelContext<'a> {
    pub fn string_attr(&self, attr: MetricTagCelAttr) -> Option<&'a str> {
        match attr {
            MetricTagCelAttr::SourceWorkload => Some(self.source_workload),
            MetricTagCelAttr::SourceNamespace => Some(self.source_namespace),
            MetricTagCelAttr::SourcePrincipal => Some(self.source_principal),
            MetricTagCelAttr::SourceApp => Some(self.source_app),
            MetricTagCelAttr::SourceService => Some(self.source_service),
            MetricTagCelAttr::DestinationWorkload => Some(self.destination_workload),
            MetricTagCelAttr::DestinationNamespace => Some(self.destination_namespace),
            MetricTagCelAttr::DestinationPrincipal => Some(self.destination_principal),
            MetricTagCelAttr::DestinationApp => Some(self.destination_app),
            MetricTagCelAttr::DestinationService => Some(self.destination_service),
            MetricTagCelAttr::RequestProtocol => Some(self.request_protocol),
            MetricTagCelAttr::ResponseFlags => Some(self.response_flags),
            MetricTagCelAttr::ConnectionSecurityPolicy => Some(self.connection_security_policy),
            MetricTagCelAttr::RequestMethod => self.request_method.filter(|v| !v.is_empty()),
            MetricTagCelAttr::RequestHost => self.request_host.filter(|v| !v.is_empty()),
            MetricTagCelAttr::ResponseCode | MetricTagCelAttr::DestinationPort => None,
        }
    }

    pub fn int_attr(&self, attr: MetricTagCelAttr) -> Option<u16> {
        match attr {
            MetricTagCelAttr::ResponseCode => self.response_code,
            MetricTagCelAttr::DestinationPort => self.destination_port,
            _ => None,
        }
    }
}

/// Parse a Telemetry UPSERT `value` that is not a JSON double-quoted literal.
///
/// Diagnostics are field-specific and never echo the operator-controlled
/// expression text (it may contain credentials or control characters).
pub fn parse_metric_tag_cel_expression(expr: &str) -> Result<MetricTagCelExpr, String> {
    if expr.len() > MAX_METRIC_TAG_CEL_EXPR_LEN {
        return Err(format!(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum length of {MAX_METRIC_TAG_CEL_EXPR_LEN} bytes"
        ));
    }
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("Telemetry metrics.overrides[].tagOverrides UPSERT value is required".into());
    }
    let mut parser = CelParser::new(trimmed);
    let parsed = parser.parse_expression()?;
    parser.expect_end()?;
    let compiled = canonicalize(parsed)?;
    validate_metric_tag_cel_expr(&compiled)?;
    Ok(compiled)
}

/// Reject HTTP-only attributes when the override cannot be represented for the
/// selected metric family set (TCP or ALL_METRICS that includes TCP).
pub fn validate_metric_tag_cel_for_families(
    expr: &MetricTagCelExpr,
    includes_tcp: bool,
) -> Result<(), String> {
    if !includes_tcp {
        return Ok(());
    }
    if expr_uses_http_only(expr) {
        return Err(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression uses HTTP-only attributes that are unrepresentable for TCP metric families"
                .into(),
        );
    }
    Ok(())
}

pub fn validate_metric_tag_cel_expr(expr: &MetricTagCelExpr) -> Result<(), String> {
    let mut nodes = 0usize;
    walk_validate(expr, 0, &mut nodes)
}

fn walk_validate(expr: &MetricTagCelExpr, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > MAX_METRIC_TAG_CEL_NESTING {
        return Err(format!(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum nesting depth of {MAX_METRIC_TAG_CEL_NESTING}"
        ));
    }
    *nodes += 1;
    if *nodes > MAX_METRIC_TAG_CEL_AST_NODES {
        return Err(format!(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum AST size of {MAX_METRIC_TAG_CEL_AST_NODES} nodes"
        ));
    }
    match expr {
        MetricTagCelExpr::Literal { value } => {
            if value.len() > MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
                return Err(format!(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT literal exceeds {MAX_METRIC_TAG_CEL_OUTPUT_BYTES} bytes"
                ));
            }
            Ok(())
        }
        MetricTagCelExpr::Attribute { name } => {
            if name.is_int() {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL integer attributes require string()"
                        .into(),
                );
            }
            Ok(())
        }
        MetricTagCelExpr::StringOfInt { attribute } => {
            if !attribute.is_int() {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string() requires an integer attribute"
                        .into(),
                );
            }
            Ok(())
        }
        MetricTagCelExpr::HasThenElse {
            attribute,
            then_expr,
            else_expr,
        } => {
            if attribute.is_int() {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL has() requires a string attribute"
                        .into(),
                );
            }
            walk_validate(then_expr, depth + 1, nodes)?;
            walk_validate(else_expr, depth + 1, nodes)
        }
    }
}

fn expr_uses_http_only(expr: &MetricTagCelExpr) -> bool {
    match expr {
        MetricTagCelExpr::Literal { .. } => false,
        MetricTagCelExpr::Attribute { name }
        | MetricTagCelExpr::StringOfInt { attribute: name } => name.is_http_only(),
        MetricTagCelExpr::HasThenElse {
            attribute,
            then_expr,
            else_expr,
        } => {
            attribute.is_http_only()
                || expr_uses_http_only(then_expr)
                || expr_uses_http_only(else_expr)
        }
    }
}

/// Evaluate a compiled expression into a sanitized label value.
///
/// Missing attributes yield an empty string (Istio/Envoy empty-dimension
/// behavior) rather than inventing placeholder traffic data. Output is
/// truncated and sanitized to printable ASCII suitable for Prometheus labels.
// This is a public library helper exercised by the external unit-test target.
// The binary target compiles the same module independently, where the helper is
// intentionally unused because the live hot path evaluates the compact plan.
#[allow(dead_code)]
pub fn evaluate_metric_tag_cel(expr: &MetricTagCelExpr, ctx: MetricTagCelContext<'_>) -> String {
    let raw = match expr {
        MetricTagCelExpr::Literal { value } => value.clone(),
        MetricTagCelExpr::Attribute { name } => ctx.string_attr(*name).unwrap_or("").to_string(),
        MetricTagCelExpr::StringOfInt { attribute } => ctx
            .int_attr(*attribute)
            .map(|value| value.to_string())
            .unwrap_or_default(),
        MetricTagCelExpr::HasThenElse {
            attribute,
            then_expr,
            else_expr,
        } => {
            if ctx.string_attr(*attribute).is_some() {
                evaluate_metric_tag_cel(then_expr, ctx)
            } else {
                evaluate_metric_tag_cel(else_expr, ctx)
            }
        }
    };
    sanitize_metric_tag_value(&raw)
}

/// Bound and sanitize a metric label value for Prometheus emission.
pub fn sanitize_metric_tag_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(MAX_METRIC_TAG_CEL_OUTPUT_BYTES));
    for ch in value.chars() {
        if out.len() >= MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
            break;
        }
        let next = match ch {
            '"' | '\\' | '\n' | '\r' | '\t' => '_',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '_',
        };
        if out.len() + next.len_utf8() > MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
            break;
        }
        out.push(next);
    }
    out
}

/// Resolve `destination.port` from stamped metadata when present.
pub fn metadata_destination_port(metadata: &HashMap<String, String>) -> Option<u16> {
    metadata
        .get(METRIC_TAG_CEL_DESTINATION_PORT_METADATA)
        .and_then(|value| value.parse::<u16>().ok())
}

/// Resolve `request.host` from stamped metadata when present.
pub fn metadata_request_host(metadata: &HashMap<String, String>) -> Option<&str> {
    metadata
        .get(METRIC_TAG_CEL_REQUEST_HOST_METADATA)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// Resolve `request.method` from stamped metadata when present.
pub fn metadata_request_method(metadata: &HashMap<String, String>) -> Option<&str> {
    metadata
        .get(METRIC_TAG_CEL_REQUEST_METHOD_METADATA)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

// --- parser -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedExpr {
    Literal(String),
    Attribute(MetricTagCelAttr),
    StringOf(Box<ParsedExpr>),
    Has(MetricTagCelAttr),
    Ternary {
        condition: Box<ParsedExpr>,
        then_expr: Box<ParsedExpr>,
        else_expr: Box<ParsedExpr>,
    },
}

struct CelParser<'a> {
    input: &'a str,
    pos: usize,
    token_count: usize,
    paren_depth: usize,
    node_count: usize,
}

impl<'a> CelParser<'a> {
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
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<ParsedExpr, String> {
        let condition = self.parse_primary()?;
        self.skip_whitespace();
        if !self.consume_token("?")? {
            return Ok(condition);
        }
        let then_expr = self.parse_ternary()?;
        self.skip_whitespace();
        if !self.consume_token(":")? {
            return Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL ternary is missing ':'"
                    .into(),
            );
        }
        let else_expr = self.parse_ternary()?;
        self.bump_node_count()?;
        Ok(ParsedExpr::Ternary {
            condition: Box::new(condition),
            then_expr: Box::new(then_expr),
            else_expr: Box::new(else_expr),
        })
    }

    fn parse_primary(&mut self) -> Result<ParsedExpr, String> {
        self.skip_whitespace();
        if self.consume_token("(")? {
            self.paren_depth += 1;
            if self.paren_depth > MAX_METRIC_TAG_CEL_NESTING {
                return Err(format!(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum nesting depth of {MAX_METRIC_TAG_CEL_NESTING}"
                ));
            }
            let expr = self.parse_expression()?;
            self.skip_whitespace();
            if !self.consume_token(")")? {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression has unclosed '('"
                        .into(),
                );
            }
            self.paren_depth -= 1;
            return Ok(expr);
        }

        if self.peek_char() == Some('"') || self.peek_char() == Some('\'') {
            let literal = self.parse_string_literal()?;
            self.bump_node_count()?;
            return Ok(ParsedExpr::Literal(literal));
        }

        let ident = self.parse_identifier_path()?;
        if ident == "string" {
            self.skip_whitespace();
            if !self.consume_token("(")? {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string() is malformed"
                        .into(),
                );
            }
            let inner = self.parse_expression()?;
            self.skip_whitespace();
            if !self.consume_token(")")? {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string() is malformed"
                        .into(),
                );
            }
            self.bump_node_count()?;
            return Ok(ParsedExpr::StringOf(Box::new(inner)));
        }
        if ident == "has" {
            self.skip_whitespace();
            if !self.consume_token("(")? {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL has() is malformed"
                        .into(),
                );
            }
            let attr_name = self.parse_identifier_path()?;
            let Some(attr) = MetricTagCelAttr::parse(&attr_name) else {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression has unsupported attribute"
                        .into(),
                );
            };
            self.skip_whitespace();
            if !self.consume_token(")")? {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL has() is malformed"
                        .into(),
                );
            }
            self.bump_node_count()?;
            return Ok(ParsedExpr::Has(attr));
        }

        let Some(attr) = MetricTagCelAttr::parse(&ident) else {
            return Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression has unsupported attribute"
                    .into(),
            );
        };
        self.bump_node_count()?;
        Ok(ParsedExpr::Attribute(attr))
    }

    fn parse_string_literal(&mut self) -> Result<String, String> {
        let quote = self.peek_char().ok_or_else(|| {
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string literal is malformed"
                .to_string()
        })?;
        self.pos += 1;
        self.bump_token_count()?;
        let mut out = String::new();
        while let Some(ch) = self.peek_char() {
            if ch == quote {
                self.pos += 1;
                self.bump_token_count()?;
                if out.len() > MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
                    return Err(format!(
                        "Telemetry metrics.overrides[].tagOverrides UPSERT literal exceeds {MAX_METRIC_TAG_CEL_OUTPUT_BYTES} bytes"
                    ));
                }
                return Ok(out);
            }
            if ch == '\\' {
                self.pos += 1;
                let escaped = self.peek_char().ok_or_else(|| {
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string literal is malformed"
                        .to_string()
                })?;
                self.pos += 1;
                let mapped = match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' | '\'' | '"' => escaped,
                    _ => {
                        return Err(
                            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string literal has unsupported escape"
                                .into(),
                        );
                    }
                };
                if out.len() + mapped.len_utf8() > MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
                    return Err(format!(
                        "Telemetry metrics.overrides[].tagOverrides UPSERT literal exceeds {MAX_METRIC_TAG_CEL_OUTPUT_BYTES} bytes"
                    ));
                }
                out.push(mapped);
                continue;
            }
            if ch == '\n' || ch == '\r' {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string literal is malformed"
                        .into(),
                );
            }
            if out.len() + ch.len_utf8() > MAX_METRIC_TAG_CEL_OUTPUT_BYTES {
                return Err(format!(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT literal exceeds {MAX_METRIC_TAG_CEL_OUTPUT_BYTES} bytes"
                ));
            }
            out.push(ch);
            self.pos += ch.len_utf8();
        }
        Err(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string literal is malformed"
                .into(),
        )
    }

    fn parse_identifier_path(&mut self) -> Result<String, String> {
        self.skip_whitespace();
        let start = self.pos;
        let Some(first) = self.peek_char() else {
            return Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression is incomplete"
                    .into(),
            );
        };
        if !(first.is_ascii_alphabetic() || first == '_') {
            return Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression has unsupported syntax"
                    .into(),
            );
        }
        self.pos += 1;
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                self.pos += 1;
                continue;
            }
            break;
        }
        self.bump_token_count()?;
        Ok(self.input[start..self.pos].to_string())
    }

    fn expect_end(&mut self) -> Result<(), String> {
        self.skip_whitespace();
        if self.pos < self.input.len() {
            return Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression has unsupported trailing syntax"
                    .into(),
            );
        }
        Ok(())
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

    fn skip_whitespace(&mut self) {
        while self
            .peek_char()
            .is_some_and(|ch| ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
        {
            self.pos += 1;
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump_token_count(&mut self) -> Result<(), String> {
        self.token_count += 1;
        if self.token_count > MAX_METRIC_TAG_CEL_TOKENS {
            return Err(format!(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum token count of {MAX_METRIC_TAG_CEL_TOKENS}"
            ));
        }
        Ok(())
    }

    fn bump_node_count(&mut self) -> Result<(), String> {
        self.node_count += 1;
        if self.node_count > MAX_METRIC_TAG_CEL_AST_NODES {
            return Err(format!(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL expression exceeds maximum AST size of {MAX_METRIC_TAG_CEL_AST_NODES} nodes"
            ));
        }
        Ok(())
    }
}

fn canonicalize(parsed: ParsedExpr) -> Result<MetricTagCelExpr, String> {
    match parsed {
        ParsedExpr::Literal(value) => Ok(MetricTagCelExpr::Literal { value }),
        ParsedExpr::Attribute(name) => Ok(MetricTagCelExpr::Attribute { name }),
        ParsedExpr::StringOf(inner) => match canonicalize(*inner)? {
            MetricTagCelExpr::Attribute { name } if name.is_int() => {
                Ok(MetricTagCelExpr::StringOfInt { attribute: name })
            }
            MetricTagCelExpr::StringOfInt { attribute } => {
                Ok(MetricTagCelExpr::StringOfInt { attribute })
            }
            _ => Err(
                "Telemetry metrics.overrides[].tagOverrides UPSERT CEL string() requires an integer attribute"
                    .into(),
            ),
        },
        ParsedExpr::Has(_) => Err(
            "Telemetry metrics.overrides[].tagOverrides UPSERT CEL has() is only valid as a ternary condition"
                .into(),
        ),
        ParsedExpr::Ternary {
            condition,
            then_expr,
            else_expr,
        } => {
            let ParsedExpr::Has(attribute) = *condition else {
                return Err(
                    "Telemetry metrics.overrides[].tagOverrides UPSERT CEL ternary conditions only support has(<attribute>)"
                        .into(),
                );
            };
            Ok(MetricTagCelExpr::HasThenElse {
                attribute,
                then_expr: Box::new(canonicalize(*then_expr)?),
                else_expr: Box::new(canonicalize(*else_expr)?),
            })
        }
    }
}
