//! Strict, bounded RFC 8941 Structured Field Values parser.
//!
//! Only the subset the gateway verifies is implemented: Dictionaries whose
//! member values are Items or Inner Lists, with Parameters, over the bare item
//! types Integer, String, Token, Byte Sequence, and Boolean. It exists for RFC
//! 9421 HTTP Message Signatures verification (`Signature-Input` /
//! `Signature`), where the parsed structure is also re-serialized into the
//! signature base, so the parser is deliberately stricter than RFC 8941:
//!
//! * Decimals are refused (no verified field uses one).
//! * A duplicated Dictionary key or Parameter key is refused instead of the
//!   RFC's "last one wins": an ambiguous signature description is hostile
//!   input, not a value to pick from.
//! * Input length, Dictionary members, Inner List items, and Parameters are all
//!   bounded, so a hostile field costs a bounded linear scan.
//! * Byte Sequences must be canonical padded standard base64.
//!
//! Errors are fixed classifications that never echo input bytes.

use base64::Engine as _;

/// Largest field value this parser accepts, in bytes.
pub const MAX_STRUCTURED_FIELD_BYTES: usize = 8 * 1024;
/// Most members one Dictionary may carry.
pub const MAX_DICTIONARY_MEMBERS: usize = 16;
/// Most items one Inner List may carry.
pub const MAX_INNER_LIST_ITEMS: usize = 64;
/// Most Parameters one Item or Inner List may carry.
pub const MAX_PARAMETERS: usize = 16;
/// RFC 8941 §3.3.1: at most 15 decimal digits.
const MAX_INTEGER_DIGITS: usize = 15;

/// A bare item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareItem {
    Integer(i64),
    String(String),
    Token(String),
    ByteSequence(Vec<u8>),
    Boolean(bool),
}

/// Ordered Parameters (keys are unique).
pub type Parameters = Vec<(String, BareItem)>;

/// An Item: a bare item plus its Parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub bare: BareItem,
    pub params: Parameters,
}

/// An Inner List: ordered Items plus the list's own Parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerList {
    pub items: Vec<Item>,
    pub params: Parameters,
}

/// A Dictionary member value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberValue {
    Item(Item),
    InnerList(InnerList),
}

/// Ordered Dictionary (keys are unique).
pub type Dictionary = Vec<(String, MemberValue)>;

/// Fixed parse-failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredFieldError {
    /// The field value exceeds [`MAX_STRUCTURED_FIELD_BYTES`].
    TooLarge,
    /// A member, item, or parameter count bound was exceeded.
    TooMany,
    /// A Dictionary or Parameter key appears twice.
    Duplicate,
    /// Anything else that is not a well-formed value of the supported subset.
    Malformed,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn skip_sp(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }
}

fn is_tchar(byte: u8) -> bool {
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

/// Parse an RFC 8941 Dictionary field value.
pub fn parse_dictionary(input: &str) -> Result<Dictionary, StructuredFieldError> {
    if input.len() > MAX_STRUCTURED_FIELD_BYTES {
        return Err(StructuredFieldError::TooLarge);
    }
    if !input.is_ascii() {
        return Err(StructuredFieldError::Malformed);
    }
    let trimmed = input.trim_matches(' ');
    let mut cursor = Cursor {
        bytes: trimmed.as_bytes(),
        pos: 0,
    };
    let mut dictionary: Dictionary = Vec::new();
    if cursor.at_end() {
        return Err(StructuredFieldError::Malformed);
    }
    loop {
        let key = parse_key(&mut cursor)?;
        let value = if cursor.peek() == Some(b'=') {
            cursor.pos += 1;
            parse_item_or_inner_list(&mut cursor)?
        } else {
            MemberValue::Item(Item {
                bare: BareItem::Boolean(true),
                params: parse_parameters(&mut cursor)?,
            })
        };
        if dictionary.iter().any(|(existing, _)| *existing == key) {
            return Err(StructuredFieldError::Duplicate);
        }
        if dictionary.len() >= MAX_DICTIONARY_MEMBERS {
            return Err(StructuredFieldError::TooMany);
        }
        dictionary.push((key, value));
        cursor.skip_ows();
        if cursor.at_end() {
            return Ok(dictionary);
        }
        if cursor.bump() != Some(b',') {
            return Err(StructuredFieldError::Malformed);
        }
        cursor.skip_ows();
        if cursor.at_end() {
            // A trailing comma.
            return Err(StructuredFieldError::Malformed);
        }
    }
}

fn parse_key(cursor: &mut Cursor<'_>) -> Result<String, StructuredFieldError> {
    let start = cursor.pos;
    match cursor.peek() {
        Some(byte) if byte.is_ascii_lowercase() || byte == b'*' => cursor.pos += 1,
        _ => return Err(StructuredFieldError::Malformed),
    }
    while let Some(byte) = cursor.peek() {
        if byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'.' | b'*')
        {
            cursor.pos += 1;
        } else {
            break;
        }
    }
    // ASCII was checked once for the whole input.
    std::str::from_utf8(&cursor.bytes[start..cursor.pos])
        .map(str::to_string)
        .map_err(|_| StructuredFieldError::Malformed)
}

fn parse_item_or_inner_list(cursor: &mut Cursor<'_>) -> Result<MemberValue, StructuredFieldError> {
    if cursor.peek() == Some(b'(') {
        parse_inner_list(cursor).map(MemberValue::InnerList)
    } else {
        parse_item(cursor).map(MemberValue::Item)
    }
}

fn parse_inner_list(cursor: &mut Cursor<'_>) -> Result<InnerList, StructuredFieldError> {
    if cursor.bump() != Some(b'(') {
        return Err(StructuredFieldError::Malformed);
    }
    let mut items = Vec::new();
    loop {
        cursor.skip_sp();
        match cursor.peek() {
            None => return Err(StructuredFieldError::Malformed),
            Some(b')') => {
                cursor.pos += 1;
                let params = parse_parameters(cursor)?;
                return Ok(InnerList { items, params });
            }
            Some(_) => {}
        }
        if items.len() >= MAX_INNER_LIST_ITEMS {
            return Err(StructuredFieldError::TooMany);
        }
        items.push(parse_item(cursor)?);
        match cursor.peek() {
            Some(b' ' | b')') => {}
            _ => return Err(StructuredFieldError::Malformed),
        }
    }
}

fn parse_item(cursor: &mut Cursor<'_>) -> Result<Item, StructuredFieldError> {
    let bare = parse_bare_item(cursor)?;
    let params = parse_parameters(cursor)?;
    Ok(Item { bare, params })
}

fn parse_bare_item(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    match cursor.peek() {
        Some(b'-') => parse_integer(cursor),
        Some(byte) if byte.is_ascii_digit() => parse_integer(cursor),
        Some(b'"') => parse_string(cursor),
        Some(b':') => parse_byte_sequence(cursor),
        Some(b'?') => parse_boolean(cursor),
        Some(byte) if byte.is_ascii_alphabetic() || byte == b'*' => parse_token(cursor),
        _ => Err(StructuredFieldError::Malformed),
    }
}

fn parse_integer(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    let negative = if cursor.peek() == Some(b'-') {
        cursor.pos += 1;
        true
    } else {
        false
    };
    let start = cursor.pos;
    while cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
        cursor.pos += 1;
        if cursor.pos - start > MAX_INTEGER_DIGITS {
            return Err(StructuredFieldError::Malformed);
        }
    }
    if cursor.pos == start {
        return Err(StructuredFieldError::Malformed);
    }
    // Decimals are outside the supported subset.
    if cursor.peek() == Some(b'.') {
        return Err(StructuredFieldError::Malformed);
    }
    let digits = std::str::from_utf8(&cursor.bytes[start..cursor.pos])
        .map_err(|_| StructuredFieldError::Malformed)?;
    // At most 15 digits always fits an i64.
    let magnitude: i64 = digits
        .parse()
        .map_err(|_| StructuredFieldError::Malformed)?;
    Ok(BareItem::Integer(if negative {
        -magnitude
    } else {
        magnitude
    }))
}

fn parse_string(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    if cursor.bump() != Some(b'"') {
        return Err(StructuredFieldError::Malformed);
    }
    let mut out = String::new();
    loop {
        match cursor.bump() {
            None => return Err(StructuredFieldError::Malformed),
            Some(b'\\') => match cursor.bump() {
                Some(escaped @ (b'"' | b'\\')) => out.push(char::from(escaped)),
                _ => return Err(StructuredFieldError::Malformed),
            },
            Some(b'"') => return Ok(BareItem::String(out)),
            Some(byte) if (0x20..0x7f).contains(&byte) => out.push(char::from(byte)),
            Some(_) => return Err(StructuredFieldError::Malformed),
        }
    }
}

fn parse_token(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    let start = cursor.pos;
    match cursor.peek() {
        Some(byte) if byte.is_ascii_alphabetic() || byte == b'*' => cursor.pos += 1,
        _ => return Err(StructuredFieldError::Malformed),
    }
    while cursor
        .peek()
        .is_some_and(|byte| is_tchar(byte) || matches!(byte, b':' | b'/'))
    {
        cursor.pos += 1;
    }
    std::str::from_utf8(&cursor.bytes[start..cursor.pos])
        .map(|token| BareItem::Token(token.to_string()))
        .map_err(|_| StructuredFieldError::Malformed)
}

fn parse_byte_sequence(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    if cursor.bump() != Some(b':') {
        return Err(StructuredFieldError::Malformed);
    }
    let start = cursor.pos;
    loop {
        match cursor.bump() {
            None => return Err(StructuredFieldError::Malformed),
            Some(b':') => break,
            Some(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') => {}
            Some(_) => return Err(StructuredFieldError::Malformed),
        }
    }
    let encoded = &cursor.bytes[start..cursor.pos - 1];
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(BareItem::ByteSequence)
        .map_err(|_| StructuredFieldError::Malformed)
}

fn parse_boolean(cursor: &mut Cursor<'_>) -> Result<BareItem, StructuredFieldError> {
    if cursor.bump() != Some(b'?') {
        return Err(StructuredFieldError::Malformed);
    }
    match cursor.bump() {
        Some(b'1') => Ok(BareItem::Boolean(true)),
        Some(b'0') => Ok(BareItem::Boolean(false)),
        _ => Err(StructuredFieldError::Malformed),
    }
}

fn parse_parameters(cursor: &mut Cursor<'_>) -> Result<Parameters, StructuredFieldError> {
    let mut params: Parameters = Vec::new();
    while cursor.peek() == Some(b';') {
        cursor.pos += 1;
        cursor.skip_sp();
        let key = parse_key(cursor)?;
        let value = if cursor.peek() == Some(b'=') {
            cursor.pos += 1;
            parse_bare_item(cursor)?
        } else {
            BareItem::Boolean(true)
        };
        if params.iter().any(|(existing, _)| *existing == key) {
            return Err(StructuredFieldError::Duplicate);
        }
        if params.len() >= MAX_PARAMETERS {
            return Err(StructuredFieldError::TooMany);
        }
        params.push((key, value));
    }
    Ok(params)
}

/// Serialize a bare item per RFC 8941 §4.1.
pub fn serialize_bare_item(item: &BareItem, out: &mut String) {
    match item {
        BareItem::Integer(value) => out.push_str(&value.to_string()),
        BareItem::String(value) => {
            out.push('"');
            for ch in value.chars() {
                if matches!(ch, '"' | '\\') {
                    out.push('\\');
                }
                out.push(ch);
            }
            out.push('"');
        }
        BareItem::Token(value) => out.push_str(value),
        BareItem::ByteSequence(value) => {
            out.push(':');
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(value));
            out.push(':');
        }
        BareItem::Boolean(value) => out.push_str(if *value { "?1" } else { "?0" }),
    }
}

/// Serialize Parameters per RFC 8941 §4.1.1.2.
pub fn serialize_parameters(params: &Parameters, out: &mut String) {
    for (key, value) in params {
        out.push(';');
        out.push_str(key);
        if *value != BareItem::Boolean(true) {
            out.push('=');
            serialize_bare_item(value, out);
        }
    }
}

/// Serialize an Item per RFC 8941 §4.1.3.
pub fn serialize_item(item: &Item, out: &mut String) {
    serialize_bare_item(&item.bare, out);
    serialize_parameters(&item.params, out);
}

/// Serialize an Inner List per RFC 8941 §4.1.1.1.
pub fn serialize_inner_list(list: &InnerList, out: &mut String) {
    out.push('(');
    for (index, item) in list.items.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        serialize_item(item, out);
    }
    out.push(')');
    serialize_parameters(&list.params, out);
}
