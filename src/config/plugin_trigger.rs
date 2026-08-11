//! Declarative per-instance plugin execution triggers.
//!
//! A [`PluginTrigger`] is an OPTIONAL block on [`crate::config::types::PluginConfig`]
//! that decides whether that one plugin instance executes for a given request or
//! stream connection. An absent trigger preserves today's behavior exactly: the
//! instance runs whenever its scope, protocol filter, and priority say it should.
//!
//! # Design rules
//!
//! * **Strict.** Every struct is `deny_unknown_fields`. A node must carry
//!   exactly one of `all` / `any` / `not` / `match`, and a `match` leaf must
//!   carry exactly one predicate. Anything else is rejected at config load,
//!   admin write, and plugin-cache publication — never at request time.
//! * **Bounded.** Depth, node count, list length, string length, and regex size
//!   all have hard ceilings ([`MAX_TRIGGER_DEPTH`] and friends). Compilation is
//!   the only place a regex is ever built.
//! * **Deterministic.** Absent inputs never match a positive predicate.
//!   Multi-valued fields choose `any` (default) or `all` explicitly. Header
//!   names are ASCII-case-insensitive; query and cookie names are
//!   case-sensitive; values are case-sensitive unless `case_insensitive` is set.
//! * **Phase-safe.** Predicates that read authenticated identity are marked at
//!   compile time ([`CompiledPluginTrigger::reads_authenticated_identity`]) so
//!   the gate can refuse to apply them before the authentication boundary has
//!   populated them.
//!
//! The compiled form ([`CompiledPluginTrigger`]) is built once per plugin-cache
//! generation and shared through `Arc`. Request evaluation walks precompiled
//! matchers only — no parsing, no allocation, no locks.
//!
//! Evaluation adapters that bind a live `RequestContext` / `StreamConnectionContext`
//! to [`TriggerFacts`] live in `crate::plugins::trigger`.

use std::net::IpAddr;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Maximum nesting depth of the predicate tree. The root node is depth 1.
pub const MAX_TRIGGER_DEPTH: usize = 8;
/// Maximum total number of nodes (branches + leaves) in one trigger.
pub const MAX_TRIGGER_NODES: usize = 128;
/// Maximum number of entries in any value list (`exact`, `prefix`, `method`, …).
pub const MAX_TRIGGER_LIST_LEN: usize = 64;
/// Maximum byte length of any single literal match value.
pub const MAX_TRIGGER_VALUE_LEN: usize = 1024;
/// Maximum byte length of a header / query / cookie field name.
pub const MAX_TRIGGER_FIELD_NAME_LEN: usize = 256;
/// Maximum byte length of a regex pattern source.
pub const MAX_TRIGGER_REGEX_LEN: usize = 512;
/// Compiled-program size ceiling for a trigger regex, in bytes.
pub const MAX_TRIGGER_REGEX_SIZE_BYTES: usize = 64 * 1024;
/// Lazy-DFA cache ceiling for a trigger regex, in bytes.
pub const MAX_TRIGGER_REGEX_DFA_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Optional declarative execution trigger for one plugin instance.
///
/// ```yaml
/// trigger:
///   when:
///     all:
///       - match: { method: [POST, PUT] }
///       - match: { path: { prefix: ["/v1/orders"] } }
///       - not:
///           match: { header: { name: x-internal, presence: present } }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginTrigger {
    /// Predicate tree. The instance executes when this evaluates to `true`.
    pub when: PluginTriggerNode,
}

/// One node of the predicate tree. Exactly one field must be set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginTriggerNode {
    /// Logical AND. An empty list is rejected (it would be a silent tautology).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<PluginTriggerNode>>,
    /// Logical OR. An empty list is rejected (it would silently never match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<PluginTriggerNode>>,
    /// Logical NOT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<PluginTriggerNode>>,
    /// Leaf predicate.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_: Option<PluginTriggerMatch>,
}

/// A leaf predicate. Exactly one field must be set so a leaf never has to
/// define an implicit combination rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginTriggerMatch {
    /// HTTP method. Compared ASCII-case-insensitively; the list is an OR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<Vec<String>>,
    /// Canonical policy path (`crate::policy_path`) — never the raw target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PluginTriggerStringMatch>,
    /// Request authority host. Lowercased, trailing dot and port removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<PluginTriggerStringMatch>,
    /// Frontend TLS/QUIC SNI hostname, when the client supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<PluginTriggerStringMatch>,
    /// Request header field. Name is ASCII-case-insensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<PluginTriggerFieldMatch>,
    /// Query parameter of the client's original request target.
    /// Names and values are compared after percent-decoding, case-sensitively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<PluginTriggerFieldMatch>,
    /// Cookie from the request `Cookie` header. Names are case-sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<PluginTriggerFieldMatch>,
    /// Authoritative wire protocol identity. The list is an OR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Vec<PluginTriggerProtocol>>,
    /// Source address / CIDR list evaluated against the gateway-resolved client
    /// IP. The list is an OR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cidr: Option<Vec<String>>,
    /// Namespace of the matched proxy. The list is an OR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<Vec<String>>,
    /// ID of the matched proxy. The list is an OR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<Vec<String>>,
    /// Frontend listener port that accepted the request/connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<Vec<u16>>,
    /// Authenticated consumer username / external identity.
    ///
    /// Only authoritative after the authentication boundary — see the module
    /// docs and `docs/plugin_execution_order.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<PluginTriggerIdentityMatch>,
    /// Successful authentication mechanism name (e.g. `jwt_auth`). Compared
    /// ASCII-case-insensitively; the list is an OR. Post-authentication only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<Vec<String>>,
    /// Peer SPIFFE ID established by mesh/mTLS identity. Post-authentication only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<PluginTriggerIdentityMatch>,
}

/// String comparison. Exactly one of `exact` / `prefix` / `regex` must be set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginTriggerStringMatch {
    /// Full-value equality against any entry (OR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<Vec<String>>,
    /// Prefix match against any entry (OR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Vec<String>>,
    /// Anchored, size-bounded regular expression. Implicitly `^(?:…)$`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// ASCII case-insensitive comparison. Defaults to `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub case_insensitive: bool,
}

/// Presence semantics for a named field.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerPresence {
    /// The field must occur at least once.
    #[default]
    Present,
    /// The field must not occur at all. Cannot be combined with `value`.
    Absent,
}

/// How a `value` match applies when a field occurs more than once.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerMultiValue {
    /// At least one occurrence matches. Default.
    #[default]
    Any,
    /// Every occurrence matches (and at least one occurrence exists).
    All,
}

/// Header / query / cookie predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginTriggerFieldMatch {
    /// Field name.
    pub name: String,
    /// Presence requirement. Defaults to `present`.
    #[serde(default)]
    pub presence: PluginTriggerPresence,
    /// Optional value comparison. Requires `presence: present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PluginTriggerStringMatch>,
    /// Multi-occurrence semantics for `value`. Defaults to `any`.
    #[serde(default)]
    pub multi_value: PluginTriggerMultiValue,
}

/// Authenticated-identity predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginTriggerIdentityMatch {
    /// Presence requirement. Defaults to `present`.
    #[serde(default)]
    pub presence: PluginTriggerPresence,
    /// Optional value comparison. Requires `presence: present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<PluginTriggerStringMatch>,
}

/// Authoritative wire-protocol identity available to a trigger.
///
/// `http1` / `http2` / `http3` are the frontend transport stamped at intake.
/// `grpc` is a native gRPC request (`content-type: application/grpc*`),
/// `grpc_web` a recognized gRPC-Web request, `websocket` a WebSocket upgrade
/// (HTTP/1.1 `Upgrade` or RFC 8441 Extended CONNECT). `tcp` / `udp` / `dtls`
/// are stream-proxy connections.
///
/// Transport and flavor are independent: an H2 native-gRPC request matches both
/// `http2` and `grpc`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginTriggerProtocol {
    Http1,
    Http2,
    Http3,
    Grpc,
    GrpcWeb,
    Websocket,
    Tcp,
    Udp,
    Dtls,
}

impl PluginTrigger {
    /// Validate the trigger without retaining the compiled form.
    ///
    /// Shared by file-config validation and the admin API so an invalid trigger
    /// is refused before storage, and again at plugin-cache publication.
    pub fn validate(&self) -> Result<(), String> {
        CompiledPluginTrigger::compile(self).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------

/// Immutable, request-ready form of a [`PluginTrigger`].
#[derive(Debug)]
pub struct CompiledPluginTrigger {
    root: CompiledNode,
    reads_authenticated_identity: bool,
    /// First HTTP-only field name the predicate reads, if any.
    http_only_field: Option<&'static str>,
}

#[derive(Debug)]
enum CompiledNode {
    All(Vec<CompiledNode>),
    Any(Vec<CompiledNode>),
    Not(Box<CompiledNode>),
    Match(CompiledMatch),
}

#[derive(Debug)]
enum CompiledMatch {
    /// Uppercased method tokens.
    Method(Vec<Box<str>>),
    Path(CompiledStringMatch),
    Host(CompiledStringMatch),
    Sni(CompiledStringMatch),
    Header(CompiledFieldMatch),
    Query(CompiledFieldMatch),
    Cookie(CompiledFieldMatch),
    Protocol(Vec<PluginTriggerProtocol>),
    SourceCidr(Vec<CompiledCidr>),
    Namespace(Vec<Box<str>>),
    ProxyId(Vec<Box<str>>),
    ListenPort(Vec<u16>),
    Consumer(CompiledIdentityMatch),
    /// Lowercased mechanism names.
    AuthMethod(Vec<Box<str>>),
    SpiffeId(CompiledIdentityMatch),
}

#[derive(Debug)]
enum CompiledStringMatch {
    /// Case-sensitive equality against any entry.
    Exact(Vec<Box<str>>),
    /// ASCII-lowercased equality against any entry (input lowercased on the fly).
    ExactCaseInsensitive(Vec<Box<str>>),
    Prefix(Vec<Box<str>>),
    PrefixCaseInsensitive(Vec<Box<str>>),
    Regex(Regex),
}

#[derive(Debug)]
struct CompiledFieldMatch {
    /// Header names are stored ASCII-lowercased; query/cookie names verbatim.
    name: Box<str>,
    presence: PluginTriggerPresence,
    value: Option<CompiledStringMatch>,
    multi_value: PluginTriggerMultiValue,
}

#[derive(Debug)]
struct CompiledIdentityMatch {
    presence: PluginTriggerPresence,
    value: Option<CompiledStringMatch>,
}

/// One exact address or CIDR reduced to an inclusive numeric interval.
#[derive(Debug, Clone, Copy)]
struct CompiledCidr {
    is_v6: bool,
    start: u128,
    end: u128,
}

/// Callback invoked once per observed occurrence of a named field. `None`
/// means the occurrence is authoritative but its value is not representable as
/// UTF-8; it still counts for presence while matching no configured text.
/// Returning `false` stops the scan early.
pub type FieldVisitor<'a> = dyn FnMut(Option<&str>) -> bool + 'a;

/// Everything a compiled trigger can read about one request or stream
/// connection. Implemented in `crate::plugins::trigger` for the live contexts.
///
/// Every accessor is cheap: a field read, a precomputed cache read, or a
/// bounded scan of the pristine inbound header/query view.
pub trait TriggerFacts {
    /// Whether this context is an HTTP-family request. HTTP-only predicates
    /// (method / path / host / header / query / cookie) evaluate to `false` on
    /// a non-HTTP context rather than being silently skipped.
    fn is_http(&self) -> bool;
    fn method(&self) -> Option<&str>;
    fn path(&self) -> Option<&str>;
    fn host(&self) -> Option<&str>;
    fn sni(&self) -> Option<&str>;
    /// Authoritative protocol identities for this context. A request may carry
    /// more than one (transport + flavor).
    fn protocols(&self) -> &[PluginTriggerProtocol];
    fn client_ip(&self) -> Option<IpAddr>;
    fn namespace(&self) -> Option<&str>;
    fn proxy_id(&self) -> Option<&str>;
    fn listen_port(&self) -> Option<u16>;
    fn consumer_identity(&self) -> Option<&str>;
    fn auth_method(&self) -> Option<&str>;
    fn spiffe_id(&self) -> Option<&str>;
    /// Visit every value of the named header (name already ASCII-lowercased).
    /// `visit` returns `false` to stop the scan early.
    ///
    /// # Representability rule (all three field surfaces)
    ///
    /// A trigger compares text, but presence is a structural fact. An
    /// occurrence whose value is not valid UTF-8 is reported as `None`: it
    /// satisfies presence, but no configured value matcher. An occurrence whose
    /// name itself cannot be decoded cannot be attributed to `lower_name` and is
    /// skipped. Lossy transcoding is never used — it would let hostile bytes be
    /// coerced into `U+FFFD` and match a configured replacement character. The
    /// offending bytes are never copied, reflected, or logged.
    fn for_each_header_value(&self, lower_name: &str, visit: &mut FieldVisitor<'_>);
    /// Visit every percent-decoded value of the named query parameter. Once a
    /// decoded name matches, an invalid-UTF-8 value is reported as `None`; a
    /// name that cannot be decoded is skipped (see
    /// [`Self::for_each_header_value`]).
    fn for_each_query_value(&self, name: &str, visit: &mut FieldVisitor<'_>);
    /// Visit every value of the named cookie. Cookie lines that are not valid
    /// UTF-8 are skipped (see [`Self::for_each_header_value`]).
    fn for_each_cookie_value(&self, name: &str, visit: &mut FieldVisitor<'_>);
}

impl CompiledPluginTrigger {
    /// Compile and fully validate a trigger. Every rejection is a config error.
    pub fn compile(trigger: &PluginTrigger) -> Result<Self, String> {
        let mut budget = CompileBudget {
            nodes: 0,
            reads_authenticated_identity: false,
            http_only_field: None,
        };
        let root = compile_node(&trigger.when, 1, &mut budget)?;
        Ok(Self {
            root,
            reads_authenticated_identity: budget.reads_authenticated_identity,
            http_only_field: budget.http_only_field,
        })
    }

    /// Whether any leaf reads authenticated identity (`consumer`,
    /// `auth_method`, `spiffe_id`). Such a trigger must not gate a hook that
    /// runs at or before the authentication boundary.
    pub fn reads_authenticated_identity(&self) -> bool {
        self.reads_authenticated_identity
    }

    /// The first HTTP-only field name (`method`, `path`, `host`, `header`,
    /// `query`, `cookie`) any leaf reads, or `None`.
    ///
    /// A stream connection genuinely has no request line, header block, query
    /// string, or cookie jar. On a plugin that ALSO serves HTTP such a predicate
    /// is meaningful and evaluates to `false` for the stream leg. On a
    /// STREAM-ONLY plugin it can only ever produce a constant, so publication
    /// refuses it with this field name rather than admitting a predicate that
    /// silently disables (or, beneath `not`, silently always-enables) the
    /// instance.
    pub fn http_only_field(&self) -> Option<&'static str> {
        self.http_only_field
    }

    /// Evaluate the trigger. `true` means "execute this plugin instance".
    pub fn evaluate(&self, facts: &dyn TriggerFacts) -> bool {
        eval_node(&self.root, facts)
    }
}

/// Remember the first HTTP-only field a predicate reads, for stream-only
/// publication refusal. First occurrence wins so the diagnostic is stable.
fn note_http_only_field(budget: &mut CompileBudget, field: &'static str) {
    if budget.http_only_field.is_none() {
        budget.http_only_field = Some(field);
    }
}

struct CompileBudget {
    nodes: usize,
    reads_authenticated_identity: bool,
    http_only_field: Option<&'static str>,
}

fn compile_node(
    node: &PluginTriggerNode,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<CompiledNode, String> {
    if depth > MAX_TRIGGER_DEPTH {
        return Err(format!(
            "trigger: predicate tree deeper than the {MAX_TRIGGER_DEPTH}-level limit"
        ));
    }
    budget.nodes += 1;
    if budget.nodes > MAX_TRIGGER_NODES {
        return Err(format!(
            "trigger: predicate tree exceeds the {MAX_TRIGGER_NODES}-node limit"
        ));
    }

    let set = usize::from(node.all.is_some())
        + usize::from(node.any.is_some())
        + usize::from(node.not.is_some())
        + usize::from(node.match_.is_some());
    if set != 1 {
        return Err(
            "trigger: each node must set exactly one of `all`, `any`, `not`, or `match`"
                .to_string(),
        );
    }

    if let Some(children) = &node.all {
        let compiled = compile_children(children, "all", depth, budget)?;
        return Ok(CompiledNode::All(compiled));
    }
    if let Some(children) = &node.any {
        let compiled = compile_children(children, "any", depth, budget)?;
        return Ok(CompiledNode::Any(compiled));
    }
    if let Some(child) = &node.not {
        return Ok(CompiledNode::Not(Box::new(compile_node(
            child,
            depth + 1,
            budget,
        )?)));
    }
    let leaf = node
        .match_
        .as_ref()
        .ok_or_else(|| "trigger: empty node".to_string())?;
    Ok(CompiledNode::Match(compile_match(leaf, budget)?))
}

fn compile_children(
    children: &[PluginTriggerNode],
    label: &str,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<Vec<CompiledNode>, String> {
    if children.is_empty() {
        return Err(format!(
            "trigger: `{label}` must contain at least one child node; an empty list has no defined truth value"
        ));
    }
    if children.len() > MAX_TRIGGER_LIST_LEN {
        return Err(format!(
            "trigger: `{label}` has {} children, over the {MAX_TRIGGER_LIST_LEN} limit",
            children.len()
        ));
    }
    children
        .iter()
        .map(|child| compile_node(child, depth + 1, budget))
        .collect()
}

fn compile_match(
    leaf: &PluginTriggerMatch,
    budget: &mut CompileBudget,
) -> Result<CompiledMatch, String> {
    let set = usize::from(leaf.method.is_some())
        + usize::from(leaf.path.is_some())
        + usize::from(leaf.host.is_some())
        + usize::from(leaf.sni.is_some())
        + usize::from(leaf.header.is_some())
        + usize::from(leaf.query.is_some())
        + usize::from(leaf.cookie.is_some())
        + usize::from(leaf.protocol.is_some())
        + usize::from(leaf.source_cidr.is_some())
        + usize::from(leaf.namespace.is_some())
        + usize::from(leaf.proxy_id.is_some())
        + usize::from(leaf.listen_port.is_some())
        + usize::from(leaf.consumer.is_some())
        + usize::from(leaf.auth_method.is_some())
        + usize::from(leaf.spiffe_id.is_some());
    if set != 1 {
        return Err(
            "trigger: each `match` leaf must set exactly one predicate; combine predicates with `all` / `any` / `not`"
                .to_string(),
        );
    }

    if let Some(methods) = &leaf.method {
        note_http_only_field(budget, "method");
        let list = compile_token_list(methods, "method", |value| value.to_ascii_uppercase())?;
        for method in &list {
            if !method.bytes().all(is_http_token_byte) {
                return Err(format!(
                    "trigger: `method` entry {method:?} is not a valid HTTP token"
                ));
            }
        }
        return Ok(CompiledMatch::Method(list));
    }
    if let Some(value) = &leaf.path {
        note_http_only_field(budget, "path");
        return Ok(CompiledMatch::Path(compile_string_match(value, "path")?));
    }
    if let Some(value) = &leaf.host {
        note_http_only_field(budget, "host");
        return Ok(CompiledMatch::Host(compile_string_match(value, "host")?));
    }
    if let Some(value) = &leaf.sni {
        return Ok(CompiledMatch::Sni(compile_string_match(value, "sni")?));
    }
    if let Some(field) = &leaf.header {
        note_http_only_field(budget, "header");
        return Ok(CompiledMatch::Header(compile_field_match(
            field, "header", true,
        )?));
    }
    if let Some(field) = &leaf.query {
        note_http_only_field(budget, "query");
        return Ok(CompiledMatch::Query(compile_field_match(
            field, "query", false,
        )?));
    }
    if let Some(field) = &leaf.cookie {
        note_http_only_field(budget, "cookie");
        return Ok(CompiledMatch::Cookie(compile_field_match(
            field, "cookie", false,
        )?));
    }
    if let Some(protocols) = &leaf.protocol {
        if protocols.is_empty() {
            return Err("trigger: `protocol` must list at least one protocol".to_string());
        }
        if protocols.len() > MAX_TRIGGER_LIST_LEN {
            return Err(format!(
                "trigger: `protocol` has {} entries, over the {MAX_TRIGGER_LIST_LEN} limit",
                protocols.len()
            ));
        }
        return Ok(CompiledMatch::Protocol(protocols.clone()));
    }
    if let Some(rules) = &leaf.source_cidr {
        if rules.is_empty() {
            return Err(
                "trigger: `source_cidr` must list at least one address or CIDR".to_string(),
            );
        }
        if rules.len() > MAX_TRIGGER_LIST_LEN {
            return Err(format!(
                "trigger: `source_cidr` has {} entries, over the {MAX_TRIGGER_LIST_LEN} limit",
                rules.len()
            ));
        }
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            compiled.push(compile_cidr(rule)?);
        }
        return Ok(CompiledMatch::SourceCidr(compiled));
    }
    if let Some(values) = &leaf.namespace {
        return Ok(CompiledMatch::Namespace(compile_token_list(
            values,
            "namespace",
            str::to_string,
        )?));
    }
    if let Some(values) = &leaf.proxy_id {
        return Ok(CompiledMatch::ProxyId(compile_token_list(
            values,
            "proxy_id",
            str::to_string,
        )?));
    }
    if let Some(ports) = &leaf.listen_port {
        if ports.is_empty() {
            return Err("trigger: `listen_port` must list at least one port".to_string());
        }
        if ports.len() > MAX_TRIGGER_LIST_LEN {
            return Err(format!(
                "trigger: `listen_port` has {} entries, over the {MAX_TRIGGER_LIST_LEN} limit",
                ports.len()
            ));
        }
        if ports.contains(&0) {
            return Err("trigger: `listen_port` entries must be 1-65535".to_string());
        }
        return Ok(CompiledMatch::ListenPort(ports.clone()));
    }
    if let Some(identity) = &leaf.consumer {
        budget.reads_authenticated_identity = true;
        return Ok(CompiledMatch::Consumer(compile_identity_match(
            identity, "consumer",
        )?));
    }
    if let Some(values) = &leaf.auth_method {
        budget.reads_authenticated_identity = true;
        return Ok(CompiledMatch::AuthMethod(compile_token_list(
            values,
            "auth_method",
            |value| value.to_ascii_lowercase(),
        )?));
    }
    let identity = leaf
        .spiffe_id
        .as_ref()
        .ok_or_else(|| "trigger: empty `match` leaf".to_string())?;
    budget.reads_authenticated_identity = true;
    Ok(CompiledMatch::SpiffeId(compile_identity_match(
        identity,
        "spiffe_id",
    )?))
}

/// RFC 9110 `tchar`.
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn compile_token_list(
    values: &[String],
    label: &str,
    normalize: impl Fn(&str) -> String,
) -> Result<Vec<Box<str>>, String> {
    if values.is_empty() {
        return Err(format!("trigger: `{label}` must list at least one value"));
    }
    if values.len() > MAX_TRIGGER_LIST_LEN {
        return Err(format!(
            "trigger: `{label}` has {} entries, over the {MAX_TRIGGER_LIST_LEN} limit",
            values.len()
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        check_value_len(value, label)?;
        if value.is_empty() {
            return Err(format!("trigger: `{label}` entries must not be empty"));
        }
        out.push(normalize(value).into_boxed_str());
    }
    Ok(out)
}

fn check_value_len(value: &str, label: &str) -> Result<(), String> {
    if value.len() > MAX_TRIGGER_VALUE_LEN {
        return Err(format!(
            "trigger: `{label}` value is {} bytes, over the {MAX_TRIGGER_VALUE_LEN}-byte limit",
            value.len()
        ));
    }
    Ok(())
}

fn compile_string_match(
    value: &PluginTriggerStringMatch,
    label: &str,
) -> Result<CompiledStringMatch, String> {
    let set = usize::from(value.exact.is_some())
        + usize::from(value.prefix.is_some())
        + usize::from(value.regex.is_some());
    if set != 1 {
        return Err(format!(
            "trigger: `{label}` must set exactly one of `exact`, `prefix`, or `regex`"
        ));
    }
    if let Some(values) = &value.exact {
        let list = compile_token_list(values, label, |entry| {
            if value.case_insensitive {
                entry.to_ascii_lowercase()
            } else {
                entry.to_string()
            }
        })?;
        return Ok(if value.case_insensitive {
            CompiledStringMatch::ExactCaseInsensitive(list)
        } else {
            CompiledStringMatch::Exact(list)
        });
    }
    if let Some(values) = &value.prefix {
        let list = compile_token_list(values, label, |entry| {
            if value.case_insensitive {
                entry.to_ascii_lowercase()
            } else {
                entry.to_string()
            }
        })?;
        return Ok(if value.case_insensitive {
            CompiledStringMatch::PrefixCaseInsensitive(list)
        } else {
            CompiledStringMatch::Prefix(list)
        });
    }
    let pattern = value
        .regex
        .as_ref()
        .ok_or_else(|| format!("trigger: `{label}` regex missing"))?;
    if pattern.is_empty() {
        return Err(format!("trigger: `{label}` regex must not be empty"));
    }
    if pattern.len() > MAX_TRIGGER_REGEX_LEN {
        return Err(format!(
            "trigger: `{label}` regex is {} bytes, over the {MAX_TRIGGER_REGEX_LEN}-byte limit",
            pattern.len()
        ));
    }
    // Anchor so a trigger regex can never partially match a longer value, and
    // bound both the compiled program and the lazy-DFA cache so a hostile
    // pattern cannot turn one config write into unbounded memory.
    let anchored = format!("^(?:{pattern})$");
    let compiled = regex::RegexBuilder::new(&anchored)
        .case_insensitive(value.case_insensitive)
        .size_limit(MAX_TRIGGER_REGEX_SIZE_BYTES)
        .dfa_size_limit(MAX_TRIGGER_REGEX_DFA_BYTES)
        .build()
        .map_err(|error| format!("trigger: `{label}` regex is invalid or too large: {error}"))?;
    Ok(CompiledStringMatch::Regex(compiled))
}

fn compile_field_match(
    field: &PluginTriggerFieldMatch,
    label: &str,
    lowercase_name: bool,
) -> Result<CompiledFieldMatch, String> {
    // Deliberately NOT trimmed. The strict rule below promises printable ASCII
    // without whitespace, and silently normalizing `" x-tier "` into `x-tier`
    // would admit a padded name as another configured field — a difference an
    // operator reading the config back could not see.
    let name = field.name.as_str();
    if name.is_empty() {
        return Err(format!("trigger: `{label}.name` must not be empty"));
    }
    if name.len() > MAX_TRIGGER_FIELD_NAME_LEN {
        return Err(format!(
            "trigger: `{label}.name` is {} bytes, over the {MAX_TRIGGER_FIELD_NAME_LEN}-byte limit",
            name.len()
        ));
    }
    if name.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(format!(
            "trigger: `{label}.name` must be printable ASCII without whitespace"
        ));
    }
    if lowercase_name && !name.bytes().all(is_http_token_byte) {
        return Err(format!(
            "trigger: `{label}.name` {name:?} is not a valid HTTP field name"
        ));
    }
    if field.presence == PluginTriggerPresence::Absent && field.value.is_some() {
        return Err(format!(
            "trigger: `{label}` cannot combine `presence: absent` with `value`; an absent field has no value to compare"
        ));
    }
    let value = field
        .value
        .as_ref()
        .map(|value| compile_string_match(value, &format!("{label}.value")))
        .transpose()?;
    Ok(CompiledFieldMatch {
        name: if lowercase_name {
            name.to_ascii_lowercase().into_boxed_str()
        } else {
            name.to_string().into_boxed_str()
        },
        presence: field.presence,
        value,
        multi_value: field.multi_value,
    })
}

fn compile_identity_match(
    identity: &PluginTriggerIdentityMatch,
    label: &str,
) -> Result<CompiledIdentityMatch, String> {
    if identity.presence == PluginTriggerPresence::Absent && identity.value.is_some() {
        return Err(format!(
            "trigger: `{label}` cannot combine `presence: absent` with `value`"
        ));
    }
    let value = identity
        .value
        .as_ref()
        .map(|value| compile_string_match(value, &format!("{label}.value")))
        .transpose()?;
    Ok(CompiledIdentityMatch {
        presence: identity.presence,
        value,
    })
}

fn compile_cidr(rule: &str) -> Result<CompiledCidr, String> {
    let invalid = || format!("trigger: `source_cidr` entry {rule:?} is not a valid IP or CIDR");
    check_value_len(rule, "source_cidr")?;
    let (address, prefix) = match rule.split_once('/') {
        Some((address, prefix)) => {
            let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
            (address, Some(prefix))
        }
        None => (rule, None),
    };
    let parsed: IpAddr = address.trim().parse().map_err(|_| invalid())?;
    match parsed {
        IpAddr::V4(ip) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err(invalid());
            }
            let value = u32::from(ip);
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = value & mask;
            Ok(CompiledCidr {
                is_v6: false,
                start: u128::from(start),
                end: u128::from(start | !mask),
            })
        }
        IpAddr::V6(ip) => {
            // Normalize IPv4-mapped literals onto the v4 space so an operator
            // rule and a mapped peer address compare in one family.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                let prefix = match prefix {
                    Some(prefix) => prefix.checked_sub(96).ok_or_else(invalid)?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(invalid());
                }
                let value = u32::from(mapped);
                let mask = if prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - prefix)
                };
                let start = value & mask;
                return Ok(CompiledCidr {
                    is_v6: false,
                    start: u128::from(start),
                    end: u128::from(start | !mask),
                });
            }
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err(invalid());
            }
            let value = u128::from(ip);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let start = value & mask;
            Ok(CompiledCidr {
                is_v6: true,
                start,
                end: start | !mask,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn eval_node(node: &CompiledNode, facts: &dyn TriggerFacts) -> bool {
    match node {
        CompiledNode::All(children) => children.iter().all(|child| eval_node(child, facts)),
        CompiledNode::Any(children) => children.iter().any(|child| eval_node(child, facts)),
        CompiledNode::Not(child) => !eval_node(child, facts),
        CompiledNode::Match(leaf) => eval_match(leaf, facts),
    }
}

fn eval_match(leaf: &CompiledMatch, facts: &dyn TriggerFacts) -> bool {
    match leaf {
        CompiledMatch::Method(methods) => {
            facts.is_http()
                && facts.method().is_some_and(|method| {
                    methods
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(method))
                })
        }
        CompiledMatch::Path(matcher) => {
            facts.is_http()
                && facts
                    .path()
                    .is_some_and(|path| matches_string(matcher, path))
        }
        CompiledMatch::Host(matcher) => {
            facts.is_http()
                && facts
                    .host()
                    .is_some_and(|host| matches_string(matcher, host))
        }
        // SNI is a transport fact, available on HTTP and stream contexts alike.
        CompiledMatch::Sni(matcher) => facts.sni().is_some_and(|sni| matches_string(matcher, sni)),
        CompiledMatch::Header(field) => {
            facts.is_http() && matches_field(field, FieldKind::Header, facts)
        }
        CompiledMatch::Query(field) => {
            facts.is_http() && matches_field(field, FieldKind::Query, facts)
        }
        CompiledMatch::Cookie(field) => {
            facts.is_http() && matches_field(field, FieldKind::Cookie, facts)
        }
        CompiledMatch::Protocol(wanted) => {
            let observed = facts.protocols();
            wanted.iter().any(|candidate| observed.contains(candidate))
        }
        CompiledMatch::SourceCidr(rules) => facts.client_ip().is_some_and(|ip| {
            let (is_v6, value) = canonical_ip_value(ip);
            rules
                .iter()
                .any(|rule| rule.is_v6 == is_v6 && value >= rule.start && value <= rule.end)
        }),
        CompiledMatch::Namespace(values) => facts
            .namespace()
            .is_some_and(|value| values.iter().any(|entry| &**entry == value)),
        CompiledMatch::ProxyId(values) => facts
            .proxy_id()
            .is_some_and(|value| values.iter().any(|entry| &**entry == value)),
        CompiledMatch::ListenPort(ports) => facts
            .listen_port()
            .is_some_and(|port| ports.contains(&port)),
        CompiledMatch::Consumer(identity) => matches_identity(identity, facts.consumer_identity()),
        CompiledMatch::AuthMethod(values) => facts
            .auth_method()
            .is_some_and(|value| values.iter().any(|entry| entry.eq_ignore_ascii_case(value))),
        CompiledMatch::SpiffeId(identity) => matches_identity(identity, facts.spiffe_id()),
    }
}

fn canonical_ip_value(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(ip) => (false, u128::from(u32::from(ip))),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(mapped) => (false, u128::from(u32::from(mapped))),
            None => (true, u128::from(ip)),
        },
    }
}

fn matches_identity(identity: &CompiledIdentityMatch, observed: Option<&str>) -> bool {
    match identity.presence {
        PluginTriggerPresence::Absent => observed.is_none_or(str::is_empty),
        PluginTriggerPresence::Present => match (&identity.value, observed) {
            (_, None) => false,
            (_, Some("")) => false,
            (None, Some(_)) => true,
            (Some(matcher), Some(value)) => matches_string(matcher, value),
        },
    }
}

/// Which named-field surface a leaf reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Header,
    Query,
    Cookie,
}

fn matches_field(field: &CompiledFieldMatch, kind: FieldKind, facts: &dyn TriggerFacts) -> bool {
    let want_all = field.multi_value == PluginTriggerMultiValue::All;
    let matcher = field.value.as_ref();
    let mut seen = false;
    let mut any_matched = false;
    let mut all_matched = true;
    {
        let mut visit = |value: Option<&str>| -> bool {
            seen = true;
            let Some(matcher) = matcher else {
                // Presence-only: one occurrence settles it.
                return false;
            };
            let Some(value) = value else {
                // The field occurred, but hostile/non-text bytes can satisfy no
                // text matcher. `all` is settled false; `any` keeps scanning for
                // another representable occurrence that may match.
                all_matched = false;
                return !want_all;
            };
            if matches_string(matcher, value) {
                any_matched = true;
                // `any` is settled by the first match, so it stops; `all` is not
                // — a later occurrence can still be a miss — so it keeps going.
                want_all
            } else {
                all_matched = false;
                // `all` is settled by the first miss, so it stops; `any` is not
                // — a later occurrence can still match — so it keeps going.
                !want_all
            }
        };
        match kind {
            FieldKind::Header => facts.for_each_header_value(&field.name, &mut visit),
            FieldKind::Query => facts.for_each_query_value(&field.name, &mut visit),
            FieldKind::Cookie => facts.for_each_cookie_value(&field.name, &mut visit),
        }
    }
    match (field.presence, matcher) {
        // An absent field is exactly "no occurrence was observed".
        (PluginTriggerPresence::Absent, _) => !seen,
        (PluginTriggerPresence::Present, None) => seen,
        (PluginTriggerPresence::Present, Some(_)) => {
            seen && if want_all { all_matched } else { any_matched }
        }
    }
}

fn matches_string(matcher: &CompiledStringMatch, value: &str) -> bool {
    match matcher {
        CompiledStringMatch::Exact(candidates) => {
            candidates.iter().any(|candidate| &**candidate == value)
        }
        CompiledStringMatch::ExactCaseInsensitive(candidates) => candidates
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value)),
        CompiledStringMatch::Prefix(candidates) => candidates
            .iter()
            .any(|candidate| value.starts_with(&**candidate)),
        CompiledStringMatch::PrefixCaseInsensitive(candidates) => {
            candidates.iter().any(|candidate| {
                value.len() >= candidate.len()
                    && value.is_char_boundary(candidate.len())
                    && value[..candidate.len()].eq_ignore_ascii_case(candidate)
            })
        }
        CompiledStringMatch::Regex(regex) => regex.is_match(value),
    }
}
