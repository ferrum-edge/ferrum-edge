//! Request-header views for backend dispatch (issue #6671).
//!
//! A routed request normally projects its wire `HeaderMap` into the
//! plugin-facing [`crate::plugins::RequestContext::headers`] map, and every
//! dispatcher then rebuilds an outbound `HeaderMap` from those owned strings.
//! When no plugin can observe or change the request (an empty resolved chain
//! on a plain HTTP/1.x or HTTP/2 route without path-parameter captures) and
//! the wire header block has a shape for which that map is a 1:1 projection,
//! the proxy skips the projection and dispatches from the wire map instead
//! ("passthrough").
//!
//! [`raw_request_headers_passthrough_eligible`] defines that shape: every
//! name occurs once, every value is UTF-8 that `HeaderValue::from_str`
//! accepts unchanged, and no name is a reserved gateway assertion. For such a
//! block the materialized map is exactly `{name: value}` per wire field, plus
//! the `:authority` → `Host` backfill and the re-asserted `X-Ferrum-Hops`
//! count. [`RequestHeaders`] exposes both representations through one read
//! API with that equivalence, and [`RequestHeaders::to_map`] rebuilds the
//! exact materialized map for any consumer that still needs one.

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::BuildHasher;

use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::proxy::hop_limit::{PROXY_HOPS_HEADER, proxy_hops_literal};

static HOST_HEADER_NAME: HeaderName = http::header::HOST;

/// Single-name request-header lookup shared by the materialized map and the
/// passthrough view, for helpers that read only a few named fields.
pub(crate) trait RequestHeaderLookup {
    /// The field value exactly as the materialized request map holds it.
    fn request_header(&self, name: &str) -> Option<&str>;

    fn has_request_header(&self, name: &str) -> bool {
        self.request_header(name).is_some()
    }
}

impl<S: BuildHasher> RequestHeaderLookup for HashMap<String, String, S> {
    fn request_header(&self, name: &str) -> Option<&str> {
        self.get(name).map(String::as_str)
    }
}

impl RequestHeaderLookup for RequestHeaders<'_> {
    fn request_header(&self, name: &str) -> Option<&str> {
        self.get(name)
    }
}

/// Whether the plugin-facing map of `raw` would be a 1:1 projection of it.
///
/// Materialization folds repeated names into one joined value, drops values
/// that are not UTF-8 and reserved gateway-assertion names, and the outbound
/// builders drop values `HeaderValue::from_str` refuses. A block needing any of
/// that stays on the materialized path, so passthrough never has to reproduce
/// those rules.
pub(crate) fn raw_request_headers_passthrough_eligible(raw: &HeaderMap) -> bool {
    raw.len() == raw.keys_len()
        && raw.iter().all(|(name, value)| {
            !crate::plugins::RequestContext::is_reserved_gateway_assertion_header(name.as_str())
                && value_forwards_unchanged(value)
        })
}

/// `value` decodes as UTF-8 (so materialization keeps it) and every byte is
/// one `HeaderValue::from_str` accepts (so the outbound rebuild keeps it
/// byte-for-byte).
fn value_forwards_unchanged(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    std::str::from_utf8(bytes).is_ok()
        && bytes
            .iter()
            .all(|&byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f))
}

fn wire_text(value: &HeaderValue) -> Option<&str> {
    std::str::from_utf8(value.as_bytes()).ok()
}

/// Per-request passthrough state kept on the request context: the edits the
/// routed request would otherwise have written into its materialized map.
#[derive(Clone, Debug)]
pub(crate) struct RequestHeaderPassthrough {
    /// `Host` synthesized from the HTTP/2 `:authority` when the wire block
    /// carried none.
    host_backfill: Option<HeaderValue>,
    /// The `X-Ferrum-Hops` count re-asserted before dispatch, once known.
    proxy_hops: Option<u8>,
}

impl RequestHeaderPassthrough {
    /// Passthrough state for an eligible `raw` block, or `None` when the
    /// request must keep the materialized path.
    pub(crate) fn begin(raw: &HeaderMap, authority: Option<&str>) -> Option<Self> {
        if !raw_request_headers_passthrough_eligible(raw) {
            return None;
        }
        let host_backfill = match authority {
            Some(authority) if !raw.contains_key(http::header::HOST) => {
                let value = HeaderValue::from_str(authority).ok()?;
                if !value_forwards_unchanged(&value) {
                    return None;
                }
                Some(value)
            }
            _ => None,
        };
        Some(Self {
            host_backfill,
            proxy_hops: None,
        })
    }

    pub(crate) fn set_proxy_hops(&mut self, hops: Option<u8>) {
        self.proxy_hops = hops;
    }

    pub(crate) fn view<'a>(&'a self, raw: &'a HeaderMap) -> PassthroughRequestHeaders<'a> {
        PassthroughRequestHeaders {
            raw,
            host_backfill: self
                .host_backfill
                .as_ref()
                .filter(|_| !raw.contains_key(http::header::HOST)),
            proxy_hops: self.proxy_hops,
        }
    }

    /// Apply the backfill and hop re-assertion to a map just materialized from
    /// the same raw block, leaving it identical to the eagerly built map.
    pub(crate) fn apply_to_materialized(&self, headers: &mut HashMap<String, String>) {
        if let Some(host) = self.host_backfill.as_ref()
            && !headers.contains_key("host")
            && let Some(text) = wire_text(host)
        {
            headers.insert("host".to_owned(), text.to_owned());
        }
        crate::proxy::hop_limit::reassert_outbound_proxy_hops_in_map(self.proxy_hops, headers);
    }
}

/// Borrowed passthrough view: the wire map plus the core-owned edits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PassthroughRequestHeaders<'a> {
    raw: &'a HeaderMap,
    host_backfill: Option<&'a HeaderValue>,
    proxy_hops: Option<u8>,
}

impl<'a> PassthroughRequestHeaders<'a> {
    fn get(self, name: &str) -> Option<&'a str> {
        // Materialized keys are the lowercase wire names, so a mixed-case
        // lookup misses there; `HeaderMap` would normalize it and hit.
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        if name == PROXY_HOPS_HEADER
            && let Some(hops) = self.proxy_hops
        {
            return Some(proxy_hops_literal(hops));
        }
        let raw: &'a HeaderMap = self.raw;
        match raw.get(name) {
            Some(value) => wire_text(value),
            None if name == "host" => self.host_backfill.and_then(wire_text),
            None => None,
        }
    }

    fn len(self) -> usize {
        let hops_added = self.proxy_hops.is_some() && !self.raw.contains_key(PROXY_HOPS_HEADER);
        self.raw.len() + usize::from(self.host_backfill.is_some()) + usize::from(hops_added)
    }

    fn entries(self) -> PassthroughEntries<'a> {
        PassthroughEntries {
            raw: self.raw.iter(),
            view: self,
            saw_hops: false,
            tail: 0,
        }
    }

    fn to_map(self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(self.len());
        for entry in self.entries() {
            map.insert(entry.name.to_owned(), entry.value.to_owned());
        }
        map
    }
}

/// One request field as backend dispatch forwards it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestHeaderEntry<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
    /// The wire name and value when they forward unchanged, so dispatch can
    /// clone them instead of parsing `name` / `value` again.
    wire: Option<(&'a HeaderName, &'a HeaderValue)>,
}

impl RequestHeaderEntry<'_> {
    /// The wire name and value when the field forwards unchanged.
    pub(crate) fn wire(&self) -> Option<(&HeaderName, &HeaderValue)> {
        self.wire
    }
}

pub(crate) struct PassthroughEntries<'a> {
    raw: http::header::Iter<'a, HeaderValue>,
    view: PassthroughRequestHeaders<'a>,
    saw_hops: bool,
    /// 0: wire fields, 1: host backfill, 2: appended hop count, 3: done.
    tail: u8,
}

impl<'a> Iterator for PassthroughEntries<'a> {
    type Item = RequestHeaderEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.tail == 0 {
            for (name, value) in self.raw.by_ref() {
                let Some(text) = wire_text(value) else {
                    continue;
                };
                if name.as_str() == PROXY_HOPS_HEADER {
                    self.saw_hops = true;
                    if let Some(hops) = self.view.proxy_hops {
                        let literal = proxy_hops_literal(hops);
                        if literal != text {
                            return Some(RequestHeaderEntry {
                                name: PROXY_HOPS_HEADER,
                                value: literal,
                                wire: None,
                            });
                        }
                    }
                }
                return Some(RequestHeaderEntry {
                    name: name.as_str(),
                    value: text,
                    wire: Some((name, value)),
                });
            }
            self.tail = 1;
        }
        if self.tail == 1 {
            self.tail = 2;
            if let Some(host) = self.view.host_backfill
                && let Some(text) = wire_text(host)
            {
                return Some(RequestHeaderEntry {
                    name: "host",
                    value: text,
                    wire: Some((&HOST_HEADER_NAME, host)),
                });
            }
        }
        if self.tail == 2 {
            self.tail = 3;
            if !self.saw_hops
                && let Some(hops) = self.view.proxy_hops
            {
                return Some(RequestHeaderEntry {
                    name: PROXY_HOPS_HEADER,
                    value: proxy_hops_literal(hops),
                    wire: None,
                });
            }
        }
        None
    }
}

/// The request headers a backend dispatcher forwards: the plugin-facing
/// materialized map, or the passthrough view of the wire block.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestHeaders<'a> {
    Materialized(&'a HashMap<String, String>),
    Passthrough(PassthroughRequestHeaders<'a>),
}

impl<'a> From<&'a HashMap<String, String>> for RequestHeaders<'a> {
    fn from(map: &'a HashMap<String, String>) -> Self {
        Self::Materialized(map)
    }
}

impl<'a> RequestHeaders<'a> {
    /// The field value exactly as the materialized map holds it.
    pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
        match *self {
            Self::Materialized(map) => map.get(name).map(String::as_str),
            Self::Passthrough(view) => view.get(name),
        }
    }

    pub(crate) fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub(crate) fn len(&self) -> usize {
        match *self {
            Self::Materialized(map) => map.len(),
            Self::Passthrough(view) => view.len(),
        }
    }

    /// Every field the materialized map would hold, in unspecified order.
    pub(crate) fn entries(&self) -> RequestHeaderEntries<'a> {
        match *self {
            Self::Materialized(map) => RequestHeaderEntries::Materialized(map.iter()),
            Self::Passthrough(view) => RequestHeaderEntries::Passthrough(view.entries()),
        }
    }

    /// The materialized map: borrowed as-is, or rebuilt from a passthrough
    /// view for a consumer that has not been taught the view.
    pub(crate) fn to_map(&self) -> Cow<'a, HashMap<String, String>> {
        match *self {
            Self::Materialized(map) => Cow::Borrowed(map),
            Self::Passthrough(view) => Cow::Owned(view.to_map()),
        }
    }

    /// The map handed to request-body plugin hooks. Those hooks only iterate
    /// `plugins`, so with none to run a passthrough view lends an empty map
    /// instead of materializing one nobody reads.
    pub(crate) fn for_plugin_hooks(&self, has_plugins: bool) -> Cow<'a, HashMap<String, String>> {
        match *self {
            Self::Passthrough(_) if !has_plugins => Cow::Owned(HashMap::new()),
            _ => self.to_map(),
        }
    }

    /// Names listed in the request's `Connection` field, lowercased.
    pub(crate) fn connection_listed(&self) -> Vec<String> {
        match *self {
            Self::Materialized(map) => {
                crate::proxy::headers::parse_connection_listed_from_str_map(map)
            }
            Self::Passthrough(view) => {
                crate::proxy::headers::parse_connection_listed_from_str_values(
                    view.get("connection"),
                )
            }
        }
    }
}

pub(crate) enum RequestHeaderEntries<'a> {
    Materialized(std::collections::hash_map::Iter<'a, String, String>),
    Passthrough(PassthroughEntries<'a>),
}

impl<'a> Iterator for RequestHeaderEntries<'a> {
    type Item = RequestHeaderEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Materialized(iter) => iter.next().map(|(name, value)| RequestHeaderEntry {
                name: name.as_str(),
                value: value.as_str(),
                wire: None,
            }),
            Self::Passthrough(iter) => iter.next(),
        }
    }
}
