use std::collections::BTreeSet;

use crate::tls::source::subscription::WatchedMaterialSource;
use crate::tls::source::{CertSource, MaterialKind};

pub(crate) fn push_watched_tls_source(
    sources: &mut Vec<WatchedMaterialSource>,
    seen: &mut BTreeSet<(MaterialKind, String)>,
    label: &'static str,
    source_value: Option<&str>,
    kind: MaterialKind,
) {
    let Some(source_value) = source_value else {
        return;
    };
    if source_value.trim().is_empty() {
        return;
    }

    let source = CertSource::parse(source_value.to_string(), kind);
    if seen.insert((kind, source.pool_key_component())) {
        sources.push(WatchedMaterialSource::new(label, source, kind));
    }
}
