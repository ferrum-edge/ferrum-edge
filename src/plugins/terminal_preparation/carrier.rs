//! One allocation-backed selected response. Each occurrence owns its lineage;
//! equal bytes and renamed names never change the origin of a value.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Span {
    offset: u32,
    length: u32,
}

impl Span {
    fn range(self) -> std::ops::Range<usize> {
        self.offset as usize..(self.offset + self.length) as usize
    }
}

#[derive(Clone, Copy)]
struct Field {
    name: Span,
    value: Span,
    lineage: TerminalFieldLineage,
}

#[derive(Clone, Copy)]
enum Source {
    Existing(Span),
    Name(u8),
    Value(u8),
    Final(Span),
    VaryName,
    Empty,
}

#[derive(Clone, Copy)]
struct Projection {
    name: Source,
    value: Source,
    lineage: TerminalFieldLineage,
}

#[derive(Clone, Copy)]
struct TokenContribution {
    name: Span,
    token: Span,
    lineage: TerminalFieldLineage,
    authored: bool,
}

struct VaryPlan {
    field: usize,
    missing: u8,
    required: u8,
    lineage: TerminalFieldLineage,
    wildcard: bool,
}

pub(super) const CORS_VARY_TOKENS: [&[u8]; 3] = [
    b"Origin",
    b"Access-Control-Request-Method",
    b"Access-Control-Request-Headers",
];

fn trimmed_token(value: &[u8]) -> &[u8] {
    match std::str::from_utf8(value) {
        Ok(value) => value.trim().as_bytes(),
        Err(_) => value.trim_ascii(),
    }
}

fn trim_span(bytes: &[u8], span: Span) -> Span {
    let value = &bytes[span.range()];
    let trimmed = trimmed_token(value);
    let start = trimmed.as_ptr() as usize - value.as_ptr() as usize;
    Span {
        offset: span.offset + start as u32,
        length: trimmed.len() as u32,
    }
}

fn token_span(bytes: &[u8], span: Span, wanted: &[u8]) -> Option<Span> {
    let mut offset = span.offset;
    for token in bytes[span.range()].split(|byte| *byte == b',') {
        let span = trim_span(
            bytes,
            Span {
                offset,
                length: token.len() as u32,
            },
        );
        if bytes[span.range()].eq_ignore_ascii_case(wanted) {
            return Some(span);
        }
        offset += token.len() as u32 + 1;
    }
    None
}

/// Field table and byte arena have separately checked allocation layouts. The
/// projection table fits in the SAME 32768-byte allowance while patching; no
/// second byte arena or header-map snapshot is created.
pub struct SelectedTerminalCarrier {
    fields: FixedSlots<Field>,
    bytes: AllocationBlock,
    contributions: FixedSlots<Option<TokenContribution>>,
    contribution_capacity: usize,
    used: usize,
    ticket: TerminalTicket,
    pristine_event_stream: Option<bool>,
}

impl SelectedTerminalCarrier {
    pub(crate) fn load_legacy(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        validate_terminal_headers(headers)?;
        self.fields.clear();
        self.contributions.clear();
        self.used = 0;
        let unknown = TerminalFieldLineage {
            origin: TerminalFieldOrigin::Unknown,
            policy_contribution: false,
            section: TerminalFieldSection::Initial,
            epoch: 0,
        };
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("set-cookie") {
                for value in value.split('\n') {
                    self.push(name, value.as_bytes(), unknown)?;
                }
            } else {
                self.push(name, value.as_bytes(), unknown)?;
            }
        }
        Ok(())
    }

    pub fn new(ticket: &TerminalTicket) -> Result<Self, TerminalAdmissionError> {
        let table = AllocationPlan::array::<Field>(MAX_FIELD_OCCURRENCES)?;
        let projection = AllocationPlan::array::<Option<Projection>>(MAX_FIELD_OCCURRENCES)?;
        let arena = AllocationPlan::array::<u8>(CARRIER_OWNED_BYTES)?;
        let overhead = table
            .backing_bytes()
            .saturating_add(projection.backing_bytes())
            .saturating_add(std::mem::size_of::<Self>());
        if overhead > CARRIER_OVERHEAD_BYTES || arena.backing_bytes() > CARRIER_OWNED_BYTES {
            return Err(capacity_error(
                TerminalRefusal::AllocatorUnavailable,
                overhead,
                CARRIER_OVERHEAD_BYTES,
            ));
        }
        // Derive token storage from the existing overhead allowance and actual
        // allocator classes. Exhaustion is carrier capacity, not a new cap.
        let available = CARRIER_OVERHEAD_BYTES - overhead;
        let mut contribution_capacity =
            available / std::mem::size_of::<Option<TokenContribution>>();
        while AllocationPlan::array::<Option<TokenContribution>>(contribution_capacity)?
            .backing_bytes()
            > available
        {
            contribution_capacity -= 1;
        }
        Ok(Self {
            fields: FixedSlots::request(MAX_FIELD_OCCURRENCES, ticket)?,
            bytes: AllocationBlock::zeroed_request(arena, ticket)?,
            contributions: FixedSlots::request(contribution_capacity, ticket)?,
            contribution_capacity,
            used: 0,
            ticket: ticket.clone(),
            pristine_event_stream: None,
        })
    }

    pub(crate) fn validate_ticket(
        &self,
        ticket: &TerminalTicket,
    ) -> Result<(), TerminalAdmissionError> {
        if !self.ticket.ptr_eq(ticket) {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        Ok(())
    }

    pub(crate) fn set_pristine_event_stream(&mut self, event_stream: Option<bool>) {
        self.pristine_event_stream = event_stream;
    }

    pub(crate) fn original_response_is_event_stream(&self) -> bool {
        self.pristine_event_stream.unwrap_or_else(|| {
            // Match the ordinary hook's canonical HashMap lookup exactly;
            // media-type essence comparison itself is case insensitive.
            self.occurrences()
                .find(|(name, _, _)| *name == b"content-type")
                .and_then(|(_, value, _)| std::str::from_utf8(value).ok())
                .is_some_and(super::super::utils::sse::is_text_event_stream_media_type)
        })
    }

    pub fn field_count(&self) -> usize {
        self.fields.as_slice().len()
    }

    pub fn append_cookie(&mut self, cookie: &TerminalCookie) -> Result<(), TerminalAdmissionError> {
        cookie.validate_ticket(Some(&self.ticket))?;
        let lines = cookie.value.as_str().split('\n');
        let mut count = self.field_count();
        let mut required = self.used;
        for value in lines.clone() {
            if value.len() > MAX_FIELD_VALUE_BYTES
                || value
                    .bytes()
                    .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
            {
                return Err(capacity_error(
                    TerminalRefusal::FieldCapacity,
                    value.len(),
                    MAX_FIELD_VALUE_BYTES,
                ));
            }
            count += 1;
            required = required.saturating_add(10).saturating_add(value.len());
        }
        if count > MAX_FIELD_OCCURRENCES || required > CARRIER_OWNED_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                required,
                CARRIER_OWNED_BYTES,
            ));
        }
        for value in lines {
            self.push("set-cookie", value.as_bytes(), cookie.lineage)?;
        }
        Ok(())
    }

    pub fn occurrences(&self) -> impl Iterator<Item = (&[u8], &[u8], TerminalFieldLineage)> + Clone {
        self.fields.as_slice().iter().map(|field| {
            (
                &self.bytes.bytes()[field.name.range()],
                &self.bytes.bytes()[field.value.range()],
                field.lineage,
            )
        })
    }

    /// Exact token co-ownership, including a gateway ensure satisfied by an
    /// unchanged backend token. Equal bytes do not promote backend origin.
    pub fn token_contributions(
        &self,
    ) -> impl Iterator<Item = (&[u8], &[u8], TerminalFieldLineage, bool)> {
        self.contributions.as_slice().iter().flatten().map(|token| {
            (
                &self.bytes.bytes()[token.name.range()],
                &self.bytes.bytes()[token.token.range()],
                token.lineage,
                token.authored,
            )
        })
    }

    /// Value segments expose mixed append origin without relabeling the base
    /// field. Separators immediately preceding authored tokens share that origin.
    pub fn value_segments(
        &self,
        name: &str,
    ) -> impl Iterator<Item = (&[u8], TerminalFieldLineage)> {
        self.fields
            .as_slice()
            .iter()
            .filter(move |field| {
                self.bytes.bytes()[field.name.range()].eq_ignore_ascii_case(name.as_bytes())
            })
            .flat_map(move |field| {
                let mut offset = field.value.offset;
                std::iter::from_fn(move || {
                    let end = field.value.offset + field.value.length;
                    if offset == end {
                        return None;
                    }
                    let next = self
                        .contributions
                        .as_slice()
                        .iter()
                        .flatten()
                        .filter(|token| token.authored && token.name == field.name)
                        .filter(|token| token.token.offset >= offset)
                        .min_by_key(|token| token.token.offset);
                    if let Some(token) = next {
                        let start = token.token.offset.saturating_sub(2).max(field.value.offset);
                        if offset < start {
                            let bytes = &self.bytes.bytes()[offset as usize..start as usize];
                            offset = start;
                            return Some((bytes, field.lineage));
                        }
                        let finish = token.token.offset + token.token.length;
                        let bytes = &self.bytes.bytes()[offset as usize..finish as usize];
                        offset = finish;
                        Some((bytes, token.lineage))
                    } else {
                        let bytes = &self.bytes.bytes()[offset as usize..end as usize];
                        offset = end;
                        Some((bytes, field.lineage))
                    }
                })
            })
    }

    /// Ingress is borrowed; no excess caller capacity or foreign map backing is
    /// adopted. Cookie lines enter individually, preserving opaque duplicates.
    pub fn push(
        &mut self,
        name: &str,
        value: &[u8],
        lineage: TerminalFieldLineage,
    ) -> Result<(), TerminalAdmissionError> {
        validate_field(name, "")?;
        if value.len() > MAX_FIELD_VALUE_BYTES
            || value
                .iter()
                .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
            || self.field_count() == MAX_FIELD_OCCURRENCES
        {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                value.len(),
                MAX_FIELD_VALUE_BYTES,
            ));
        }
        let required = self
            .used
            .saturating_add(name.len())
            .saturating_add(value.len());
        if required > CARRIER_OWNED_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                required,
                CARRIER_OWNED_BYTES,
            ));
        }
        // Origin/section/epoch are fixed before either copy takes place.
        let field = Field {
            name: Span {
                offset: self.used as u32,
                length: name.len() as u32,
            },
            value: Span {
                offset: (self.used + name.len()) as u32,
                length: value.len() as u32,
            },
            lineage,
        };
        self.bytes.bytes_mut()[field.name.range()].copy_from_slice(name.as_bytes());
        self.bytes.bytes_mut()[field.value.range()].copy_from_slice(value);
        self.fields.push(field)?;
        self.used = required;
        Ok(())
    }

    fn source<'a>(
        &'a self,
        source: Source,
        patch: &'a TerminalPatch,
    ) -> Result<&'a [u8], TerminalAdmissionError> {
        match source {
            Source::VaryName => Ok(b"vary"),
            Source::Empty => Ok(b""),
            Source::Existing(span) | Source::Final(span) => Ok(&self.bytes.bytes()[span.range()]),
            Source::Name(index) | Source::Value(index) => {
                let Some(TerminalFieldAction::Set { name, value, .. }) =
                    patch.actions.as_slice().get(index as usize)
                else {
                    return Err(capacity_error(
                        TerminalRefusal::UnimplementedOperation,
                        0,
                        0,
                    ));
                };
                if matches!(source, Source::Name(_)) {
                    Ok(name.as_str().as_bytes())
                } else {
                    Ok(value.as_str().as_bytes())
                }
            }
        }
    }

    /// Preflight the WHOLE patch before mutating bytes or fields. Suppressed
    /// writes retain their original lineage, including identical backend bytes.
    pub fn apply(&mut self, patch: &TerminalPatch) -> Result<(), TerminalAdmissionError> {
        patch.validate_ticket(Some(&self.ticket))?;
        let mut projected = FixedSlots::request(MAX_FIELD_OCCURRENCES, &self.ticket)?;
        let mut vary_action = None;
        for field in self.fields.as_slice() {
            projected.push(Some(Projection {
                name: Source::Existing(field.name),
                value: Source::Existing(field.value),
                lineage: field.lineage,
            }))?;
        }
        for (index, action) in patch.actions.as_slice().iter().enumerate() {
            if vary_action.is_some() {
                return Err(capacity_error(
                    TerminalRefusal::UnimplementedOperation,
                    0,
                    0,
                ));
            }
            let (name, value, override_existing, case_insensitive, lineage) = match action {
                TerminalFieldAction::CorsVary { preflight, lineage } => {
                    vary_action = Some((*preflight, *lineage));
                    continue;
                }
                TerminalFieldAction::RemovePrefix(prefix) => {
                    for field in projected.as_mut_slice() {
                        if let Some(existing) = field {
                            let name = self.source(existing.name, patch)?;
                            if name.get(..prefix.as_str().len()).is_some_and(|name| {
                                name.eq_ignore_ascii_case(prefix.as_str().as_bytes())
                            }) {
                                *field = None;
                            }
                        }
                    }
                    continue;
                }
                TerminalFieldAction::Remove(name) => (name.as_str(), None, true, true, None),
                TerminalFieldAction::Set {
                    name,
                    value,
                    override_existing,
                    case_insensitive,
                    lineage,
                } => (
                    name.as_str(),
                    Some(value.as_str()),
                    *override_existing,
                    *case_insensitive,
                    Some(*lineage),
                ),
                TerminalFieldAction::Metadata { .. } => {
                    return Err(capacity_error(
                        TerminalRefusal::UnimplementedOperation,
                        0,
                        0,
                    ));
                }
            };
            let mut exists = false;
            for field in projected.as_slice().iter().flatten() {
                let old = self.source(field.name, patch)?;
                exists |= old.eq_ignore_ascii_case(name.as_bytes());
            }
            if value.is_some() && !override_existing && exists {
                continue;
            }
            for field in projected.as_mut_slice() {
                if let Some(existing) = field {
                    let old = self.source(existing.name, patch)?;
                    let matches = if case_insensitive {
                        old.eq_ignore_ascii_case(name.as_bytes())
                    } else {
                        old == name.as_bytes()
                    };
                    if matches {
                        *field = None;
                    }
                }
            }
            if let Some(lineage) = lineage {
                let field = Some(Projection {
                    name: Source::Name(index as u8),
                    value: Source::Value(index as u8),
                    lineage,
                });
                if let Some(empty) = projected
                    .as_mut_slice()
                    .iter_mut()
                    .find(|field| field.is_none())
                {
                    *empty = field;
                } else {
                    projected.push(field)?;
                }
            }
        }
        let vary = if let Some((preflight, lineage)) = vary_action {
            Some(self.plan_vary(&mut projected, patch, preflight, lineage)?)
        } else {
            None
        };
        let mut required = 0usize;
        for field in projected.as_slice().iter().flatten() {
            required = required
                .saturating_add(self.source(field.name, patch)?.len())
                .saturating_add(self.source(field.value, patch)?.len());
        }
        if let Some(vary) = &vary {
            let field = projected.as_slice()[vary.field]
                .as_ref()
                .ok_or_else(|| capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0))?;
            let mut value_length = self.source(field.value, patch)?.len();
            for (index, token) in CORS_VARY_TOKENS.iter().enumerate() {
                if vary.missing & (1 << index) != 0 {
                    value_length += token.len() + if value_length == 0 { 0 } else { 2 };
                }
            }
            if value_length > MAX_FIELD_VALUE_BYTES {
                return Err(capacity_error(
                    TerminalRefusal::FieldCapacity,
                    value_length,
                    MAX_FIELD_VALUE_BYTES,
                ));
            }
            required =
                required.saturating_add(value_length - self.source(field.value, patch)?.len());
            let retained = self
                .contributions
                .as_slice()
                .iter()
                .flatten()
                .filter(|token| Self::retains_token(projected.as_slice(), token))
                .count();
            let additions = if vary.wildcard {
                0
            } else {
                vary.required.count_ones() as usize
            };
            if retained + additions > self.contribution_capacity {
                return Err(capacity_error(
                    TerminalRefusal::FieldCapacity,
                    retained + additions,
                    self.contribution_capacity,
                ));
            }
        }
        if required > CARRIER_OWNED_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                required,
                CARRIER_OWNED_BYTES,
            ));
        }
        // Compact retained ranges in increasing source-offset order. Moving a
        // range down never overwrites an unread range. New patch bytes append
        // only after every retained range is safe. All indices/sizes below were
        // constructed and validated above while the immutable patch was held.
        for contribution in self.contributions.as_mut_slice() {
            if contribution
                .as_ref()
                .is_some_and(|token| !Self::retains_token(projected.as_slice(), token))
            {
                *contribution = None;
            }
        }
        let mut used = 0usize;
        loop {
            let next = projected
                .as_slice()
                .iter()
                .flatten()
                .flat_map(|field| [field.name, field.value])
                .filter_map(|source| match source {
                    Source::Existing(span) => Some(span),
                    _ => None,
                })
                .min_by_key(|span| span.offset);
            let Some(span) = next else {
                break;
            };
            for token in self.contributions.as_mut_slice().iter_mut().flatten() {
                if token.name == span {
                    token.name.offset = used as u32;
                }
                if token.token.offset >= span.offset
                    && token.token.offset + token.token.length <= span.offset + span.length
                {
                    token.token.offset = used as u32 + token.token.offset - span.offset;
                }
            }
            self.bytes.bytes_mut().copy_within(span.range(), used);
            let final_span = Span {
                offset: used as u32,
                length: span.length,
            };
            used += span.length as usize;
            for field in projected.as_mut_slice().iter_mut().flatten() {
                for source in [&mut field.name, &mut field.value] {
                    if matches!(*source, Source::Existing(old) if old == span) {
                        *source = Source::Final(final_span);
                    }
                }
            }
        }
        for field in projected.as_mut_slice().iter_mut().flatten() {
            for source in [&mut field.name, &mut field.value] {
                let (index, name) = match *source {
                    Source::Name(index) => (index, true),
                    Source::Value(index) => (index, false),
                    Source::VaryName => {
                        let span = Span {
                            offset: used as u32,
                            length: 4,
                        };
                        self.bytes.bytes_mut()[span.range()].copy_from_slice(b"vary");
                        used += 4;
                        *source = Source::Final(span);
                        continue;
                    }
                    Source::Empty => {
                        *source = Source::Final(Span {
                            offset: used as u32,
                            length: 0,
                        });
                        continue;
                    }
                    _ => continue,
                };
                let Some(TerminalFieldAction::Set {
                    name: key, value, ..
                }) = patch.actions.as_slice().get(index as usize)
                else {
                    return Err(capacity_error(
                        TerminalRefusal::UnimplementedOperation,
                        0,
                        0,
                    ));
                };
                let bytes = if name {
                    key.as_str().as_bytes()
                } else {
                    value.as_str().as_bytes()
                };
                let span = Span {
                    offset: used as u32,
                    length: bytes.len() as u32,
                };
                self.bytes.bytes_mut()[span.range()].copy_from_slice(bytes);
                used += bytes.len();
                *source = Source::Final(span);
            }
        }
        if let Some(vary) = vary {
            self.commit_vary(&mut projected, &vary, &mut used)?;
        }
        self.fields.clear();
        for field in projected.as_slice().iter().flatten() {
            if let (Source::Final(name), Source::Final(value)) = (field.name, field.value) {
                self.fields.push(Field {
                    name,
                    value,
                    lineage: field.lineage,
                })?;
            }
        }
        self.used = used;
        Ok(())
    }

    fn retains_token(projected: &[Option<Projection>], token: &TokenContribution) -> bool {
        projected.iter().flatten().any(|field| {
            matches!(field.name, Source::Existing(name) if name == token.name)
                && matches!(field.value, Source::Existing(value)
                    if token.token.offset >= value.offset
                        && token.token.offset + token.token.length <= value.offset + value.length)
        })
    }

    fn plan_vary(
        &self,
        projected: &mut FixedSlots<Option<Projection>>,
        patch: &TerminalPatch,
        preflight: bool,
        lineage: TerminalFieldLineage,
    ) -> Result<VaryPlan, TerminalAdmissionError> {
        let mut target = None;
        let mut present = 0u8;
        let mut wildcard = false;
        for (index, field) in projected.as_slice().iter().enumerate() {
            let Some(field) = field else {
                continue;
            };
            if !self
                .source(field.name, patch)?
                .eq_ignore_ascii_case(b"vary")
            {
                continue;
            }
            if target.is_none() || self.source(field.name, patch)? == b"vary" {
                target = Some(index);
            }
            let value = self.source(field.value, patch)?;
            for token in value.split(|byte| *byte == b',') {
                let token = trimmed_token(token);
                wildcard |= token == b"*";
                for (index, required) in CORS_VARY_TOKENS.iter().enumerate() {
                    if token.eq_ignore_ascii_case(required) {
                        present |= 1 << index;
                    }
                }
            }
        }
        let field = if let Some(index) = target {
            if let Some(Projection {
                value: Source::Existing(span),
                ..
            }) = projected.as_mut_slice()[index].as_mut()
            {
                *span = trim_span(self.bytes.bytes(), *span);
            }
            index
        } else {
            let field = Some(Projection {
                name: Source::VaryName,
                value: Source::Empty,
                lineage,
            });
            if let Some(index) = projected.as_slice().iter().position(Option::is_none) {
                projected.as_mut_slice()[index] = field;
                index
            } else {
                let index = projected.as_slice().len();
                projected.push(field)?;
                index
            }
        };
        Ok(VaryPlan {
            field,
            required: if preflight { 7 } else { 1 },
            missing: if wildcard {
                0
            } else {
                (if preflight { 7 } else { 1 }) & !present
            },
            lineage,
            wildcard,
        })
    }

    fn commit_vary(
        &mut self,
        projected: &mut FixedSlots<Option<Projection>>,
        vary: &VaryPlan,
        used: &mut usize,
    ) -> Result<(), TerminalAdmissionError> {
        // Every range, field count, contribution slot and final byte was
        // preflighted. Insert suffix bytes in-place in the sole arena.
        let Some(Projection {
            value: Source::Final(value),
            ..
        }) = projected.as_slice()[vary.field]
        else {
            return Err(capacity_error(
                TerminalRefusal::UnimplementedOperation,
                0,
                0,
            ));
        };
        let insertion = value.offset + value.length;
        let mut additional = 0usize;
        let mut length = value.length as usize;
        for (index, token) in CORS_VARY_TOKENS.iter().enumerate() {
            if vary.missing & (1 << index) != 0 {
                let bytes = token.len() + if length == 0 { 0 } else { 2 };
                additional += bytes;
                length += bytes;
            }
        }
        self.bytes
            .bytes_mut()
            .copy_within(insertion as usize..*used, insertion as usize + additional);
        for field in projected.as_mut_slice().iter_mut().flatten() {
            for source in [&mut field.name, &mut field.value] {
                if let Source::Final(span) = source
                    && span.offset >= insertion
                {
                    span.offset += additional as u32;
                }
            }
        }
        // A zero-length target begins at the insertion point and must keep it.
        if let Some(field) = projected.as_mut_slice()[vary.field].as_mut() {
            field.value = Source::Final(Span {
                offset: value.offset,
                length: length as u32,
            });
        }
        for token in self.contributions.as_mut_slice().iter_mut().flatten() {
            if token.name.offset >= insertion {
                token.name.offset += additional as u32;
            }
            if token.token.offset >= insertion {
                token.token.offset += additional as u32;
            }
        }
        let mut offset = insertion as usize;
        let mut length = value.length as usize;
        for (index, token) in CORS_VARY_TOKENS.iter().enumerate() {
            if vary.missing & (1 << index) != 0 {
                if length != 0 {
                    self.bytes.bytes_mut()[offset..offset + 2].copy_from_slice(b", ");
                    offset += 2;
                }
                self.bytes.bytes_mut()[offset..offset + token.len()].copy_from_slice(token);
                offset += token.len();
                length += token.len() + if length == 0 { 0 } else { 2 };
            }
        }
        *used += additional;
        if vary.wildcard {
            return Ok(());
        }
        // Record all required ensures, even identical backend tokens. Their
        // authored flag distinguishes co-ownership from a newly appended byte.
        for (index, required) in CORS_VARY_TOKENS.iter().enumerate() {
            if vary.required & (1 << index) == 0 {
                continue;
            }
            for field in projected.as_slice().iter().flatten() {
                let (Source::Final(name), Source::Final(value)) = (field.name, field.value) else {
                    continue;
                };
                if !self.bytes.bytes()[name.range()].eq_ignore_ascii_case(b"vary") {
                    continue;
                }
                let Some(token) = token_span(self.bytes.bytes(), value, required) else {
                    continue;
                };
                let contribution = Some(TokenContribution {
                    name,
                    token,
                    lineage: vary.lineage,
                    authored: vary.missing & (1 << index) != 0,
                });
                if let Some(empty) = self
                    .contributions
                    .as_mut_slice()
                    .iter_mut()
                    .find(|token| token.is_none())
                {
                    *empty = contribution;
                } else {
                    // The plan proved a spare initialized-or-uninitialized slot.
                    self.contributions.push(contribution)?;
                }
                break;
            }
        }
        Ok(())
    }

    /// A rename preserves the origin, policy contribution, section and epoch.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), TerminalAdmissionError> {
        validate_field(to, "")?;
        let count = self
            .occurrences()
            .filter(|(name, _, _)| name.eq_ignore_ascii_case(from.as_bytes()))
            .count();
        let required = self.used.saturating_add(to.len().saturating_mul(count));
        if required > CARRIER_OWNED_BYTES {
            return Err(capacity_error(
                TerminalRefusal::FieldCapacity,
                required,
                CARRIER_OWNED_BYTES,
            ));
        }
        for field in self.fields.as_mut_slice() {
            if self.bytes.bytes()[field.name.range()].eq_ignore_ascii_case(from.as_bytes()) {
                let name = Span {
                    offset: self.used as u32,
                    length: to.len() as u32,
                };
                self.bytes.bytes_mut()[name.range()].copy_from_slice(to.as_bytes());
                for token in self.contributions.as_mut_slice().iter_mut().flatten() {
                    if token.name == field.name {
                        token.name = name;
                    }
                }
                field.name = name;
                self.used += to.len();
            }
        }
        Ok(())
    }
}
