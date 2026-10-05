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
}

#[derive(Clone, Copy)]
struct Projection {
    name: Source,
    value: Source,
    lineage: TerminalFieldLineage,
}

/// Field table and byte arena have separately checked allocation layouts. The
/// projection table fits in the SAME 32768-byte allowance while patching; no
/// second byte arena or header-map snapshot is created.
pub struct SelectedTerminalCarrier {
    fields: FixedSlots<Field>,
    bytes: AllocationBlock,
    used: usize,
    ticket: TerminalTicket,
}

impl SelectedTerminalCarrier {
    pub(crate) fn load_legacy(
        &mut self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        validate_terminal_headers(headers)?;
        self.fields.clear();
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
        Ok(Self {
            fields: FixedSlots::request(MAX_FIELD_OCCURRENCES, ticket)?,
            bytes: AllocationBlock::zeroed_request(arena, ticket)?,
            used: 0,
            ticket: ticket.clone(),
        })
    }

    pub fn field_count(&self) -> usize {
        self.fields.as_slice().len()
    }

    pub fn append_cookie(&mut self, cookie: &TerminalCookie) -> Result<(), TerminalAdmissionError> {
        let lines = cookie.value.as_str().split('\n');
        let mut count = self.field_count();
        let mut required = self.used;
        for value in lines.clone() {
            if value.len() > MAX_FIELD_VALUE_BYTES
                || value.bytes().any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
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

    pub fn occurrences(&self) -> impl Iterator<Item = (&[u8], &[u8], TerminalFieldLineage)> {
        self.fields.as_slice().iter().map(|field| {
            (
                &self.bytes.bytes()[field.name.range()],
                &self.bytes.bytes()[field.value.range()],
                field.lineage,
            )
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
            Source::Existing(span) | Source::Final(span) => Ok(&self.bytes.bytes()[span.range()]),
            Source::Name(index) | Source::Value(index) => {
                let Some(TerminalFieldAction::Set { name, value, .. }) =
                    patch.actions.as_slice().get(index as usize)
                else {
                    return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
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
        let mut projected = FixedSlots::request(MAX_FIELD_OCCURRENCES, &self.ticket)?;
        for field in self.fields.as_slice() {
            projected.push(Some(Projection {
                name: Source::Existing(field.name),
                value: Source::Existing(field.value),
                lineage: field.lineage,
            }))?;
        }
        for (index, action) in patch.actions.as_slice().iter().enumerate() {
            let (name, value, override_existing, case_insensitive, lineage) = match action {
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
                    return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
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
        let mut required = 0usize;
        for field in projected.as_slice().iter().flatten() {
            required = required
                .saturating_add(self.source(field.name, patch)?.len())
                .saturating_add(self.source(field.value, patch)?.len());
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
                    _ => continue,
                };
                let Some(TerminalFieldAction::Set {
                    name: key, value, ..
                }) = patch.actions.as_slice().get(index as usize)
                else {
                    return Err(capacity_error(TerminalRefusal::UnimplementedOperation, 0, 0));
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
                field.name = name;
                self.used += to.len();
            }
        }
        Ok(())
    }
}
