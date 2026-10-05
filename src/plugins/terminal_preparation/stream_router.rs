//! Closed provider-normalization action. No claim, model, credential, plugin,
//! context, request map, body, closure or future survives preparation here.

use super::*;
use crate::plugins::ai_stream_router::{
    META_PROVIDER_ENCODING, NORMALIZE_DECODE_LIMITS, ProviderEncodingRejectReason,
    ProviderStreamMediaDecision, ProviderType, classify_provider_stream_media,
};

pub struct StreamRouterTerminalDecision {
    provider: Option<ProviderType>,
    owner: u64,
    instance: TerminalInstanceToken,
    ticket: TerminalTicket,
    output_limit: usize,
}

/// Fixed JSON bodies match the ordinary hook's complete OpenAI error envelope.
/// No provider field is interpolated into an error or retained in this enum.
#[derive(Debug, Eq, PartialEq)]
pub enum StreamRouterRefusal {
    MissingMedia,
    UnexpectedMedia,
    DuplicateEncoding,
    MalformedEncoding,
    UnsupportedEncoding,
    MixedIdentity,
    TooManyLayers,
}

impl StreamRouterRefusal {
    pub const fn body(&self) -> &'static [u8] {
        macro_rules! body {
            ($message:literal, $code:literal) => {
                concat!(
                    "{\"error\":{\"message\":\"",
                    $message,
                    "\",\"type\":\"upstream_error\",\"param\":null,\"code\":\"",
                    $code,
                    "\"}}"
                )
                .as_bytes()
            };
        }
        match self {
            Self::MissingMedia => body!(
                "Upstream provider returned a successful response without a Content-Type suitable for Gemini stream normalization",
                "unsupported_content_type"
            ),
            Self::UnexpectedMedia => body!(
                "Upstream provider returned a successful response with an unexpected Content-Type for Gemini stream normalization",
                "unsupported_content_type"
            ),
            Self::DuplicateEncoding => body!(
                "ambiguous Content-Encoding field-lines",
                "unsupported_content_encoding"
            ),
            Self::MalformedEncoding => body!(
                "malformed Content-Encoding list",
                "unsupported_content_encoding"
            ),
            Self::UnsupportedEncoding => body!(
                "unsupported Content-Encoding coding",
                "unsupported_content_encoding"
            ),
            Self::MixedIdentity => body!(
                "identity Content-Encoding cannot be combined with other codings",
                "unsupported_content_encoding"
            ),
            Self::TooManyLayers => body!(
                "Content-Encoding exceeds supported coding layer count",
                "unsupported_content_encoding"
            ),
        }
    }
}

impl From<ProviderEncodingRejectReason> for StreamRouterRefusal {
    fn from(reason: ProviderEncodingRejectReason) -> Self {
        match reason {
            ProviderEncodingRejectReason::AmbiguousDuplicateFieldLines => Self::DuplicateEncoding,
            ProviderEncodingRejectReason::MalformedList => Self::MalformedEncoding,
            ProviderEncodingRejectReason::UnsupportedCoding => Self::UnsupportedEncoding,
            ProviderEncodingRejectReason::MixedIdentity => Self::MixedIdentity,
            ProviderEncodingRejectReason::TooManyLayers => Self::TooManyLayers,
        }
    }
}

/// At most four canonical gzip/br members. This is response-derived decoder
/// control, not raw header storage. Identity deliberately leaves old metadata.
struct ProviderCodingList {
    bytes: [u8; NORMALIZE_DECODE_LIMITS.max_codings * 6 - 2],
    len: usize,
}

fn encoding_output_bytes(coding: &ProviderCodingList) -> Result<usize, TerminalAdmissionError> {
    use crate::plugins::terminal_storage::global_string_plan;
    let length = coding.as_str().len();
    let patch = field_output_size_bound(1, [(META_PROVIDER_ENCODING, length)])?;
    let name = global_string_plan(META_PROVIDER_ENCODING.len())?.backing_bytes();
    let value = global_string_plan(length)?.backing_bytes();
    let custody = SharedTerminal::<TerminalMetadataCustody>::allocation_plan()?.backing_bytes();
    patch
        .checked_add(name)
        .and_then(|bytes| bytes.checked_add(value))
        .and_then(|bytes| bytes.checked_add(custody))
        .ok_or_else(|| capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0))
}

impl ProviderCodingList {
    fn as_str(&self) -> &str {
        // SAFETY: only the fixed ASCII gzip/br tokens and separators are written.
        unsafe { std::str::from_utf8_unchecked(&self.bytes[..self.len]) }
    }
}

pub struct StreamRouterTerminalOutput {
    outcome: TerminalResponseOutcome,
    fields: Option<TerminalPatch>,
    encoding: Option<ProviderCodingList>,
    owner: u64,
    instance: TerminalInstanceToken,
    ticket: TerminalTicket,
    output_limit: usize,
}

impl fmt::Debug for StreamRouterTerminalOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamRouterTerminalOutput")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl StreamRouterTerminalOutput {
    pub fn outcome(&self) -> &TerminalResponseOutcome {
        &self.outcome
    }

    pub fn provider_encoding(&self) -> Option<&str> {
        self.encoding.as_ref().map(ProviderCodingList::as_str)
    }

    /// Public destinations carry immutable request custody. There is no raw
    /// map or mutable RequestContext application surface. Consumption is once.
    pub fn apply(
        self,
        selected: &mut SelectedTerminalCarrier,
    ) -> Result<TerminalResponseOutcome, TerminalAdmissionError> {
        selected.validate_ticket(&self.ticket)?;
        if let Some(fields) = &self.fields {
            selected.apply(fields)?;
        }
        Ok(self.outcome)
    }
}

impl ReachedRequestView<'_> {
    pub(crate) fn stream_router_decision(
        &self,
        provider: Option<ProviderType>,
        owner: u64,
    ) -> Result<PreparedTerminalOp, TerminalAdmissionError> {
        let ticket = self
            .ticket
            .as_ref()
            .ok_or_else(|| capacity_error(TerminalRefusal::PinnedGeneration, 0, 0))?;
        let required = std::mem::size_of::<StreamRouterTerminalDecision>();
        if required > self.control_limit {
            return Err(capacity_error(
                TerminalRefusal::ControlCapacity,
                required,
                self.control_limit,
            ));
        }
        Ok(PreparedTerminalOp::StreamRouter(
            StreamRouterTerminalDecision {
                provider,
                owner,
                instance: self.instance,
                ticket: ticket.clone(),
                output_limit: self.output_limit,
            },
        ))
    }
}

impl StreamRouterTerminalDecision {
    pub(super) fn validate(
        &self,
        ticket: Option<&TerminalTicket>,
        instance: TerminalInstanceToken,
    ) -> Result<(), TerminalAdmissionError> {
        if self.instance != instance || ticket.is_none_or(|ticket| !ticket.ptr_eq(&self.ticket)) {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        Ok(())
    }

    /// Every response input is read here, after earlier cursor effects. The
    /// producer and destination ticket are checked before parsing/allocation.
    pub fn decide(
        self,
        status: u16,
        selected: &SelectedTerminalCarrier,
    ) -> Result<StreamRouterTerminalOutput, TerminalAdmissionError> {
        selected.validate_ticket(&self.ticket)?;
        let mut output = StreamRouterTerminalOutput {
            outcome: TerminalResponseOutcome::Continue,
            fields: None,
            encoding: None,
            owner: self.owner,
            instance: self.instance,
            ticket: self.ticket,
            output_limit: self.output_limit,
        };
        let Some(provider) = self.provider.filter(|_| (200..300).contains(&status)) else {
            return Ok(output);
        };
        // Ordinary after_proxy looks up exactly the lowercase map key.
        let media = selected
            .occurrences()
            .find(|(name, _, _)| *name == b"content-type")
            .map(|(_, value, _)| std::str::from_utf8(value))
            .transpose()
            .map_err(|_| capacity_error(TerminalRefusal::FieldCapacity, 0, 0))?;
        let refusal = match classify_provider_stream_media(provider, media) {
            ProviderStreamMediaDecision::Normalize => None,
            ProviderStreamMediaDecision::PassThrough => return Ok(output),
            ProviderStreamMediaDecision::FailClosedMissingContentType => {
                Some(StreamRouterRefusal::MissingMedia)
            }
            ProviderStreamMediaDecision::FailClosedUnexpectedContentType => {
                Some(StreamRouterRefusal::UnexpectedMedia)
            }
        };
        if let Some(refusal) = refusal {
            output.outcome = TerminalResponseOutcome::StreamRouterRefusal(refusal);
            return Ok(output);
        }
        output.encoding = match classify_encoding(selected) {
            Ok(encoding) => encoding,
            Err(reason) => {
                output.outcome = TerminalResponseOutcome::StreamRouterRefusal(reason.into());
                return Ok(output);
            }
        };
        let frame = std::mem::size_of::<StreamRouterTerminalOutput>();
        let encoding_bytes = output
            .encoding
            .as_ref()
            .map(encoding_output_bytes)
            .transpose()?
            .unwrap_or(0);
        // The canonical metadata patch and response repair can coexist. Admit
        // both native backings before allocating either patch or copying fields.
        let required = frame.checked_add(encoding_bytes).ok_or_else(|| {
            capacity_error(TerminalRefusal::ArithmeticOverflow, usize::MAX, 0)
        })?;
        let allowance = output.output_limit.checked_sub(required).ok_or_else(|| {
            capacity_error(TerminalRefusal::PatchCapacity, required, output.output_limit)
        })?;
        output.fields = Some(repair_patch(
            selected,
            allowance,
            &output.ticket,
            output.instance,
        )?);
        Ok(output)
    }
}

fn classify_encoding(
    selected: &SelectedTerminalCarrier,
) -> Result<Option<ProviderCodingList>, ProviderEncodingRejectReason> {
    use ProviderEncodingRejectReason as Reason;
    let mut values = selected
        .occurrences()
        .filter(|(name, _, _)| name.eq_ignore_ascii_case(b"content-encoding"));
    let Some((_, raw, _)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Reason::AmbiguousDuplicateFieldLines);
    }
    let raw = std::str::from_utf8(raw).map_err(|_| Reason::MalformedList)?.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let mut list = ProviderCodingList {
        bytes: [0; NORMALIZE_DECODE_LIMITS.max_codings * 6 - 2],
        len: 0,
    };
    let mut count = 0usize;
    let mut identity = false;
    let mut encoded = false;
    // Parse all members before enforcing the layer cap, preserving the ordinary
    // parser's malformed/unsupported-before-too-many error precedence.
    for member in raw.split(',') {
        let member = member.trim();
        if member.contains(';') || !crate::plugins::utils::content_encoding::is_http_token(member) {
            return Err(Reason::MalformedList);
        }
        let token = if member.eq_ignore_ascii_case("gzip") || member.eq_ignore_ascii_case("x-gzip")
        {
            encoded = true;
            "gzip"
        } else if member.eq_ignore_ascii_case("br") {
            encoded = true;
            "br"
        } else if member.eq_ignore_ascii_case("identity") {
            identity = true;
            ""
        } else {
            return Err(Reason::UnsupportedCoding);
        };
        count += 1;
        if count <= NORMALIZE_DECODE_LIMITS.max_codings && !token.is_empty() {
            if list.len != 0 {
                list.bytes[list.len..list.len + 2].copy_from_slice(b", ");
                list.len += 2;
            }
            list.bytes[list.len..list.len + token.len()].copy_from_slice(token.as_bytes());
            list.len += token.len();
        }
    }
    if count > NORMALIZE_DECODE_LIMITS.max_codings {
        return Err(Reason::TooManyLayers);
    }
    if identity && encoded {
        return Err(Reason::MixedIdentity);
    }
    Ok(encoded.then_some(list))
}

fn vary_tokens(selected: &SelectedTerminalCarrier) -> impl Iterator<Item = &str> + Clone {
    let tokens = selected
        .occurrences()
        .filter(|(name, _, _)| name.eq_ignore_ascii_case(b"vary"))
        .filter_map(|(_, value, _)| std::str::from_utf8(value).ok())
        .flat_map(|value| value.split(','))
        .map(str::trim);
    let earlier = tokens.clone();
    tokens.enumerate().filter_map(move |(index, token)| {
        (!token.is_empty()
            && !token.eq_ignore_ascii_case("accept-encoding")
            && !earlier
                .clone()
                .take(index)
                .any(|old| old.eq_ignore_ascii_case(token)))
        .then_some(token)
    })
}

fn repair_patch(
    selected: &SelectedTerminalCarrier,
    allowance: usize,
    ticket: &TerminalTicket,
    instance: TerminalInstanceToken,
) -> Result<TerminalPatch, TerminalAdmissionError> {
    use crate::plugins::{
        TRANSFORM_INVALIDATED_RESPONSE_HEADER_PREFIXES, TRANSFORM_INVALIDATED_RESPONSE_HEADERS,
    };
    let mut vary_present = false;
    let mut wildcard = false;
    let mut already_sse = false;
    for (name, value, _) in selected.occurrences() {
        if name.eq_ignore_ascii_case(b"vary") || name.eq_ignore_ascii_case(b"content-type") {
            let value = std::str::from_utf8(value)
                .map_err(|_| capacity_error(TerminalRefusal::FieldCapacity, 0, 0))?;
            if name.eq_ignore_ascii_case(b"vary") {
                vary_present = true;
                // Ordinary scrub only treats a complete field value as '*'.
                wildcard |= value.trim() == "*";
            } else {
                already_sse |= crate::plugins::utils::body_transform::is_event_stream_content_type(
                    value,
                );
            }
        }
    }
    let vary_length = if wildcard {
        1
    } else {
        joined_token_bytes(vary_tokens(selected))?
    };
    let set_vary = vary_present && vary_length != 0;
    let actions = 2
        + TRANSFORM_INVALIDATED_RESPONSE_HEADERS.len()
        + TRANSFORM_INVALIDATED_RESPONSE_HEADER_PREFIXES.len()
        + usize::from(vary_present)
        + usize::from(set_vary)
        + if already_sse { 0 } else { 2 };
    // Plan the complete output before any action table, field name/value copy,
    // rendering or arena mutation. Dynamic Vary may exhaust the approved O.
    let mut required = AllocationPlan::array::<TerminalFieldAction>(actions)?.backing_bytes();
    for name in ["content-encoding", "content-length"]
        .into_iter()
        .chain(TRANSFORM_INVALIDATED_RESPONSE_HEADERS.iter().copied())
        .chain(TRANSFORM_INVALIDATED_RESPONSE_HEADER_PREFIXES.iter().copied())
        .chain(vary_present.then_some("vary"))
        .chain((!already_sse).then_some("content-type"))
    {
        required = required.saturating_add(TerminalString::plan(name)?.backing_bytes());
    }
    if set_vary {
        required = required
            .saturating_add(TerminalString::plan("vary")?.backing_bytes())
            .saturating_add(AllocationPlan::array::<u8>(vary_length)?.backing_bytes());
    }
    if !already_sse {
        required = required
            .saturating_add(TerminalString::plan("content-type")?.backing_bytes())
            .saturating_add(TerminalString::plan("text/event-stream")?.backing_bytes());
    }
    if actions > MAX_PATCH_ACTIONS || vary_length > MAX_FIELD_VALUE_BYTES || required > allowance {
        return Err(capacity_error(
            TerminalRefusal::PatchCapacity,
            required,
            allowance,
        ));
    }
    let mut patch = TerminalPatch::new(actions, allowance, ticket, instance)?;
    patch.remove("content-encoding")?;
    patch.remove("content-length")?;
    for name in TRANSFORM_INVALIDATED_RESPONSE_HEADERS {
        patch.remove(name)?;
    }
    for prefix in TRANSFORM_INVALIDATED_RESPONSE_HEADER_PREFIXES {
        patch.remove_prefix(prefix)?;
    }
    if vary_present {
        patch.remove("vary")?;
        if wildcard {
            patch.set_policy("vary", "*", true)?;
        } else if set_vary {
            patch.set_policy_tokens("vary", vary_tokens(selected))?;
        }
    }
    if !already_sse {
        patch.remove("content-type")?;
        patch.set_policy("content-type", "text/event-stream", true)?;
    }
    Ok(patch)
}

impl PreparedTerminalChain {
    /// Core-only projection of the closed canonical coding result. The request
    /// ticket and private claim owner are checked before metadata copies. This
    /// synchronous adapter cannot expose raw state to a participant or await.
    pub(crate) fn apply_stream_router(
        &mut self,
        output: StreamRouterTerminalOutput,
        ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> Result<(), TerminalAdmissionError> {
        if self
            ._ticket
            .as_ref()
            .is_none_or(|ticket| !ticket.ptr_eq(&output.ticket))
            || ctx
                .terminal_control_reservation
                .as_ref()
                .is_none_or(|ticket| !ticket.ptr_eq(&output.ticket))
        {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        if output.fields.is_some()
            && !crate::plugins::ai_stream_router::terminal_claim_owner_matches(ctx, output.owner)
        {
            return Err(capacity_error(TerminalRefusal::PinnedGeneration, 0, 0));
        }
        if let Some(coding) = &output.encoding {
            let fields = output.fields.as_ref().map_or(0, |fields| fields.owned_bytes);
            let remaining = output
                .output_limit
                .saturating_sub(fields + std::mem::size_of::<StreamRouterTerminalOutput>());
            let mut metadata = TerminalPatch::new(
                1,
                remaining,
                &output.ticket,
                output.instance,
            )?;
            metadata.set_metadata(META_PROVIDER_ENCODING, coding.as_str())?;
            apply_terminal_metadata(metadata, ctx)?;
        }
        if let Some(fields) = output.fields {
            self.apply_fields(fields, headers)?;
        }
        // Actual C non-replacer refusals cannot replace the selected terminal.
        Ok(())
    }
}
