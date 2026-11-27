//! Admin list query primitives shared by every config store and by the
//! cached-config read path.
//!
//! The Admin API list endpoints for proxies, consumers, upstreams and plugin
//! configs accept a server-side search term (`q`) and a bounded id set
//! (`ids`). Both are evaluated in four places — PostgreSQL, MySQL and SQLite
//! (one SQL builder), MongoDB, and the in-memory config that `file`/`dp`/
//! `mesh` modes and the database-outage fallback serve from — so the matching
//! rule lives here, once, and each backend only translates it:
//!
//! - **Case folding is ASCII-only.** `A`–`Z` fold to `a`–`z`; every other
//!   character, including non-ASCII letters, compares by exact code point. No
//!   backend's locale or collation folding is used: PostgreSQL `lower()` and
//!   `ILIKE`, MySQL's `_ci` collations and MongoDB's `$options: "i"` all fold
//!   beyond ASCII (the Kelvin sign `U+212A` folds to `k` under Unicode rules,
//!   for example), and they disagree with SQLite's ASCII-only `lower()`.
//!   SQL uses SQLite `lower()` (ASCII-only by definition) or a chain of
//!   case-sensitive `REPLACE` calls on PostgreSQL and MySQL; MongoDB uses a
//!   regex whose ASCII letters are `[xX]` classes and that sets no options.
//! - **Substring, not syntax.** The term is a literal. SQL escapes the `LIKE`
//!   metacharacters (`%`, `_` and the escape character `!` itself); MongoDB
//!   escapes every ASCII punctuation character; nothing is a wildcard.
//! - **Host lists match per element.** SQL stores `Proxy.hosts` as a JSON
//!   array string, so a term that contains a JSON structural character (`"`,
//!   `\`, `,`, `[`, `]`) could only ever match across element boundaries. Such
//!   a term never matches a host on any backend (no valid hostname contains
//!   one), which keeps SQL, MongoDB and the in-memory path identical.
//! - **URL userinfo stays withheld.** The `viewer` projection of proxies and
//!   upstreams strips userinfo from URL-shaped strings. A `name` that holds
//!   such a URL must not become a search oracle for that role, so when
//!   [`ResourceListFilter::exclude_at_sign_names`] is set a `name` containing
//!   `@` (every URL with userinfo does) never matches.

use std::collections::BTreeSet;

use crate::config::types::{Consumer, PluginConfig, Proxy, Upstream};

/// Longest accepted `q`, in UTF-8 bytes.
pub const MAX_SEARCH_TERM_BYTES: usize = 256;

/// Most ids one `ids=` filter may name.
pub const MAX_LIST_IDS: usize = 100;

/// Escape character used in every SQL `LIKE` this module generates. Not a
/// backslash: MySQL treats `\` inside a string literal as an escape unless
/// `NO_BACKSLASH_ESCAPES` is set, so `ESCAPE '\'` is not portable.
pub const SQL_LIKE_ESCAPE: char = '!';

/// `config_changes.resource_type` values for the four listable collections.
pub const PROXY_RESOURCE_TYPE: &str = "proxy";
pub const CONSUMER_RESOURCE_TYPE: &str = "consumer";
pub const UPSTREAM_RESOURCE_TYPE: &str = "upstream";
pub const PLUGIN_CONFIG_RESOURCE_TYPE: &str = "plugin_config";

/// Scalar fields `q` matches, by resource kind. The names are identical as
/// SQL columns and as MongoDB document fields. `Proxy.hosts` is matched in
/// addition, per element (see [`PROXY_HOSTS_FIELD`]).
pub const PROXY_SEARCH_FIELDS: &[&str] = &["id", "name", "listen_path"];
pub const CONSUMER_SEARCH_FIELDS: &[&str] = &["id", "username", "custom_id"];
pub const UPSTREAM_SEARCH_FIELDS: &[&str] = &["id", "name"];
pub const PLUGIN_CONFIG_SEARCH_FIELDS: &[&str] = &["id", "plugin_name"];

/// The proxy host list (a JSON array string in SQL, an array in MongoDB).
pub const PROXY_HOSTS_FIELD: &str = "hosts";

/// The field [`ResourceListFilter::exclude_at_sign_names`] guards.
pub const NAME_FIELD: &str = "name";

/// A validated, ASCII-folded search term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchTerm {
    folded: String,
}

impl SearchTerm {
    /// Parse a raw `q` value. `Ok(None)` for the empty string, which means
    /// "no search" exactly as if `q` were absent. The value is otherwise used
    /// verbatim: it is not trimmed, and whitespace is significant.
    pub fn parse(raw: &str) -> Result<Option<Self>, String> {
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.len() > MAX_SEARCH_TERM_BYTES {
            return Err(format!(
                "q must be at most {MAX_SEARCH_TERM_BYTES} bytes, got {}",
                raw.len()
            ));
        }
        if raw.chars().any(char::is_control) {
            return Err("q must not contain control characters".to_string());
        }
        Ok(Some(Self {
            folded: raw.to_ascii_lowercase(),
        }))
    }

    /// The term with ASCII letters lowercased.
    pub fn folded(&self) -> &str {
        &self.folded
    }

    /// ASCII-case-insensitive substring match against one stored value.
    pub fn matches(&self, value: &str) -> bool {
        value.to_ascii_lowercase().contains(self.folded.as_str())
    }

    /// [`Self::matches`] for an optional field; an absent value never matches.
    pub fn matches_optional(&self, value: Option<&str>) -> bool {
        value.is_some_and(|value| self.matches(value))
    }

    /// Whether this term may participate in host-list matching at all.
    pub fn can_match_host_list(&self) -> bool {
        !self
            .folded
            .chars()
            .any(|c| matches!(c, '"' | '\\' | ',' | '[' | ']'))
    }

    /// Per-element host-list match.
    pub fn matches_hosts(&self, hosts: &[String]) -> bool {
        self.can_match_host_list() && hosts.iter().any(|host| self.matches(host))
    }

    /// `LIKE` pattern (with [`SQL_LIKE_ESCAPE`]) for a contains-match against
    /// an ASCII-folded column expression.
    pub fn sql_like_pattern(&self) -> String {
        let mut pattern = String::with_capacity(self.folded.len() * 2 + 2);
        pattern.push('%');
        for c in self.folded.chars() {
            if c == SQL_LIKE_ESCAPE || c == '%' || c == '_' {
                pattern.push(SQL_LIKE_ESCAPE);
            }
            pattern.push(c);
        }
        pattern.push('%');
        pattern
    }

    /// MongoDB `$regex` source (used with no options) that matches exactly
    /// what [`Self::matches`] matches: ASCII letters become `[xX]` classes,
    /// ASCII punctuation is backslash-escaped (PCRE treats a backslash before
    /// any non-alphanumeric character as that literal character), and every
    /// other character is literal.
    pub fn mongo_regex(&self) -> String {
        let mut pattern = String::with_capacity(self.folded.len() * 4);
        for c in self.folded.chars() {
            if c.is_ascii_lowercase() {
                pattern.push('[');
                pattern.push(c);
                pattern.push(c.to_ascii_uppercase());
                pattern.push(']');
            } else if c.is_ascii() && !c.is_ascii_alphanumeric() {
                pattern.push('\\');
                pattern.push(c);
            } else {
                pattern.push(c);
            }
        }
        pattern
    }
}

/// Search and id filters shared by every list endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceListFilter {
    /// `q`: ASCII-case-insensitive substring match over the kind's fields.
    pub search: Option<SearchTerm>,
    /// `ids`: exact id set; ids that do not exist are simply absent.
    pub ids: Option<Vec<String>>,
    /// Exclude `name` values containing `@` from `q` matching. Set for
    /// callers whose read projection strips URL userinfo (the `viewer` role
    /// on proxies and upstreams).
    pub exclude_at_sign_names: bool,
}

impl ResourceListFilter {
    /// Whether the filter narrows the collection at all.
    pub fn is_unfiltered(&self) -> bool {
        self.search.is_none() && self.ids.is_none()
    }

    /// In-memory evaluation, identical to the SQL and MongoDB translations.
    pub fn matches<T: ListSearchable>(&self, item: &T) -> bool {
        let search_ok = self
            .search
            .as_ref()
            .is_none_or(|term| item.matches_search(term, self.exclude_at_sign_names));
        let ids_ok = self
            .ids
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == item.list_id()));
        search_ok && ids_ok
    }
}

/// Parse an `ids` value: comma-separated resource ids, at most
/// [`MAX_LIST_IDS`], no empty element and no duplicate. Each id must satisfy
/// `validate_resource_id`.
pub fn parse_list_ids(raw: &str) -> Result<Vec<String>, String> {
    if raw.is_empty() {
        return Err("ids must name at least one id".to_string());
    }
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    for id in raw.split(',') {
        if id.is_empty() {
            return Err("ids must not contain an empty element".to_string());
        }
        if ids.len() == MAX_LIST_IDS {
            return Err(format!("ids must name at most {MAX_LIST_IDS} ids"));
        }
        crate::config::types::validate_resource_id(id).map_err(|error| format!("ids: {error}"))?;
        if !seen.insert(id) {
            return Err(format!("ids must not repeat an id ({id:?})"));
        }
        ids.push(id.to_string());
    }
    Ok(ids)
}

/// A resource the shared search rule can evaluate in memory.
pub trait ListSearchable {
    fn list_id(&self) -> &str;
    /// Whether `term` matches one of the kind's search fields. With
    /// `exclude_at_sign_names`, a `name` containing `@` never matches.
    fn matches_search(&self, term: &SearchTerm, exclude_at_sign_names: bool) -> bool;
}

fn name_matches(term: &SearchTerm, name: Option<&str>, exclude_at_sign_names: bool) -> bool {
    match name {
        Some(name) if exclude_at_sign_names && name.contains('@') => false,
        other => term.matches_optional(other),
    }
}

impl ListSearchable for Proxy {
    fn list_id(&self) -> &str {
        &self.id
    }

    fn matches_search(&self, term: &SearchTerm, exclude_at_sign_names: bool) -> bool {
        term.matches(&self.id)
            || name_matches(term, self.name.as_deref(), exclude_at_sign_names)
            || term.matches_optional(self.listen_path.as_deref())
            || term.matches_hosts(&self.hosts)
    }
}

impl ListSearchable for Consumer {
    fn list_id(&self) -> &str {
        &self.id
    }

    fn matches_search(&self, term: &SearchTerm, _exclude_at_sign_names: bool) -> bool {
        term.matches(&self.id)
            || term.matches(&self.username)
            || term.matches_optional(self.custom_id.as_deref())
    }
}

impl ListSearchable for Upstream {
    fn list_id(&self) -> &str {
        &self.id
    }

    fn matches_search(&self, term: &SearchTerm, exclude_at_sign_names: bool) -> bool {
        term.matches(&self.id) || name_matches(term, self.name.as_deref(), exclude_at_sign_names)
    }
}

impl ListSearchable for PluginConfig {
    fn list_id(&self) -> &str {
        &self.id
    }

    fn matches_search(&self, term: &SearchTerm, _exclude_at_sign_names: bool) -> bool {
        term.matches(&self.id) || term.matches(&self.plugin_name)
    }
}

/// Collection revision derived from the durable `config_changes` log.
///
/// `newest_matching` is the newest retained change sequence of the listed
/// resource types in the namespace; `oldest_retained` is the namespace's
/// oldest retained sequence of any type. The revision is `newest_matching`
/// when a matching row is retained, else `oldest_retained`, else `0`.
///
/// Why this changes on every committed create/update/delete of those types:
/// SQL stores serialize each namespace's change-log inserts on the namespace
/// lock row (so sequences become visible in commit order) and MongoDB replica
/// sets increment the counter inside the write's transaction. A new matching
/// change S is newer than every sequence the namespace had before, so either
/// it is retained (the revision becomes S) or compaction pruned it, in which
/// case the oldest retained sequence is above S. Either way the value differs
/// from any value reported before the change. Compaction alone can also move
/// the value; that only ever produces a spurious mismatch, never a missed one.
pub fn collection_revision_from_sequences(
    newest_matching: Option<u64>,
    oldest_retained: Option<u64>,
) -> u64 {
    newest_matching.or(oldest_retained).unwrap_or(0)
}
