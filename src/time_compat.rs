//! `time`-backed UTC timestamp compatibility layer for the `chrono` migration
//! (issue #7419, RUSTSEC-2026-0543).
//!
//! [`UtcTimestamp`] wraps [`time::OffsetDateTime`] normalized to
//! [`time::UtcOffset::UTC`] and preserves byte-identical serialization across:
//!
//! - **JSON / YAML / BSON (`serde`)**: RFC 3339 with `AutoSi` fractional
//!   seconds (omitted when zero, otherwise 3, 6, or 9 digits) and a `Z` UTC
//!   suffix — matching `chrono::DateTime<chrono::Utc>`'s `Serialize` impl.
//! - **SQLite (`sqlx::Sqlite`)**: `TEXT` encoded as RFC 3339 `AutoSi` with
//!   `+00:00` (`YYYY-MM-DDTHH:MM:SS[.fff|.ffffff|.fffffffff]+00:00`), matching
//!   `sqlx-sqlite`'s `chrono::DateTime<Utc>` encoder. Decoding accepts RFC 3339,
//!   legacy space-separated timestamps (`CURRENT_TIMESTAMP`
//!   `YYYY-MM-DD HH:MM:SS`, optional fractional seconds, optional offset),
//!   minute-precision timestamps, `INTEGER` Unix seconds, and `REAL` Julian day
//!   numbers (including pre-epoch values).
//! - **MySQL (`sqlx::MySql`)**: native binary `TIMESTAMP` / `DATETIME` wire
//!   packets (4, 7, or 11 payload bytes matching `sqlx-mysql`'s `chrono`
//!   encoder byte-for-byte), decoding both native binary/text `TIMESTAMP` /
//!   `DATETIME` columns and legacy `VARCHAR` / `TEXT` timestamp columns.
//! - **PostgreSQL (`sqlx::Postgres`)**: binary `TIMESTAMPTZ` `i64` microseconds
//!   since `2000-01-01T00:00:00Z` (matching `sqlx-postgres`'s `chrono` encoder
//!   byte-for-byte), decoding binary `TIMESTAMPTZ`/`TIMESTAMP`, text-protocol
//!   `TIMESTAMPTZ`/`TIMESTAMP` (including short `+00`/`-05`, `±HH:MM`, and
//!   `±HH:MM:SS` offsets with or without fractional seconds), and legacy
//!   `TEXT`/`VARCHAR` timestamp columns.
//! - **`sqlx::Any`**: text-encoded RFC 3339 (`AutoSi`, `+00:00`), matching
//!   Ferrum's existing `sqlx::Any` persistence layer (`db_loader.rs`), and
//!   decoding RFC 3339 plus legacy `CURRENT_TIMESTAMP` strings.

use std::fmt;
use std::ops::Sub;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sqlx::any::{Any, AnyTypeInfo};
use sqlx::decode::Decode;
use sqlx::encode::{Encode, IsNull};
use sqlx::error::BoxDynError;
use sqlx::mysql::{MySql, MySqlTypeInfo, MySqlValueRef};
use sqlx::postgres::{
    PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueFormat, PgValueRef, Postgres,
};
use sqlx::sqlite::{Sqlite, SqliteArgumentsBuffer, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Database, Type, TypeInfo, ValueRef};
use time::{Date, Month, OffsetDateTime, PlainDateTime, SignedDuration, Time, UtcOffset};

/// PostgreSQL binary timestamp epoch: `2000-01-01T00:00:00Z`.
const POSTGRES_EPOCH: OffsetDateTime = match Date::from_calendar_date(2000, Month::January, 1) {
    Ok(date) => PlainDateTime::new(date, Time::MIDNIGHT).assume_utc(),
    Err(_) => panic!("2000-01-01 is a valid Gregorian date"),
};

/// Minimum UTC year accepted by [`UtcTimestamp`].
///
/// Matches `time`'s default (non-`large-dates`) lower bound regardless of Cargo
/// feature unification (e.g. `bson` enabling `time/large-dates`).
const MIN_SUPPORTED_YEAR: i32 = -9999;

/// Maximum UTC year accepted by [`UtcTimestamp`].
///
/// Matches `time`'s default (non-`large-dates`) upper bound and RFC 3339's
/// 4-digit year range (`<= 9999`) regardless of Cargo feature unification.
const MAX_SUPPORTED_YEAR: i32 = 9999;

/// Fractional-second precision modes matching `chrono::SecondsFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecondsFormat {
    /// Whole seconds only (no decimal point).
    Secs,
    /// Fixed 3 fractional digits (`.sss`).
    Millis,
    /// Fixed 6 fractional digits (`.ssssss`).
    Micros,
    /// Fixed 9 fractional digits (`.sssssssss`).
    Nanos,
    /// Chrono's `AutoSi`: omit when zero, else 3 digits if millisecond-aligned,
    /// 6 digits if microsecond-aligned, or 9 digits otherwise.
    AutoSi,
}

/// Errors returned when constructing, parsing, or converting [`UtcTimestamp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// The input did not match a valid timestamp representation.
    InvalidFormat,
    /// A calendar, clock, or offset component was outside its valid range.
    InvalidComponent,
    /// The timestamp falls outside the supported date/time range of the target
    /// representation.
    OutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => f.write_str("invalid timestamp format"),
            Self::InvalidComponent => f.write_str("invalid timestamp component"),
            Self::OutOfRange => f.write_str("timestamp out of range"),
        }
    }
}

impl std::error::Error for TimestampError {}

/// A UTC timestamp backed by [`time::OffsetDateTime`] with byte-identical wire,
/// serde, and SQL compatibility with `chrono::DateTime<chrono::Utc>`.
///
/// The wrapped [`OffsetDateTime`] is always normalized to [`UtcOffset::UTC`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp(OffsetDateTime);

impl UtcTimestamp {
    /// Current wall-clock time in UTC.
    #[inline]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Validate that a UTC [`OffsetDateTime`] stays within the
    /// feature-independent `MIN_SUPPORTED_YEAR..=MAX_SUPPORTED_YEAR` range.
    #[inline]
    fn from_validated_utc(dt: OffsetDateTime) -> Result<Self, TimestampError> {
        if !(MIN_SUPPORTED_YEAR..=MAX_SUPPORTED_YEAR).contains(&dt.year()) {
            return Err(TimestampError::OutOfRange);
        }
        Ok(Self(dt))
    }

    /// Normalize an [`OffsetDateTime`] to UTC, returning
    /// [`TimestampError::OutOfRange`] if the UTC conversion would overflow
    /// [`UtcTimestamp`]'s supported year range (`-9999..=9999`).
    #[inline]
    pub fn try_from_offset_date_time(dt: OffsetDateTime) -> Result<Self, TimestampError> {
        let utc = dt
            .checked_to_offset(UtcOffset::UTC)
            .ok_or(TimestampError::OutOfRange)?;
        Self::from_validated_utc(utc)
    }

    /// Construct from a UTC [`Date`] and [`Time`].
    #[inline]
    pub const fn from_utc_date_time(date: Date, time: Time) -> Self {
        Self(PlainDateTime::new(date, time).assume_utc())
    }

    /// Return the inner UTC [`OffsetDateTime`].
    #[inline]
    pub const fn into_offset_date_time(self) -> OffsetDateTime {
        self.0
    }

    /// Return the inner UTC [`OffsetDateTime`] by value.
    #[inline]
    pub const fn as_offset_date_time(&self) -> OffsetDateTime {
        self.0
    }

    /// Construct from whole Unix epoch seconds.
    #[inline]
    pub fn from_unix_timestamp(secs: i64) -> Result<Self, TimestampError> {
        let dt =
            OffsetDateTime::from_unix_timestamp(secs).map_err(|_| TimestampError::OutOfRange)?;
        Self::from_validated_utc(dt)
    }

    /// Construct from Unix epoch seconds plus non-negative subsecond
    /// nanoseconds (`0..1_000_000_000`), matching
    /// `chrono::DateTime::from_timestamp(secs, nanos)`.
    #[inline]
    pub fn from_unix_timestamp_nanos(secs: i64, nanos: u32) -> Result<Self, TimestampError> {
        if nanos >= 1_000_000_000 {
            return Err(TimestampError::InvalidComponent);
        }
        let total = i128::from(secs)
            .checked_mul(1_000_000_000)
            .and_then(|base| base.checked_add(i128::from(nanos)))
            .ok_or(TimestampError::OutOfRange)?;
        let dt = OffsetDateTime::from_unix_timestamp_nanos(total)
            .map_err(|_| TimestampError::OutOfRange)?;
        Self::from_validated_utc(dt)
    }

    /// Construct from a [`SystemTime`] without panicking on out-of-range values.
    pub fn from_system_time(st: SystemTime) -> Result<Self, TimestampError> {
        match st.duration_since(UNIX_EPOCH) {
            Ok(dur) => {
                let secs = i64::try_from(dur.as_secs()).map_err(|_| TimestampError::OutOfRange)?;
                Self::from_unix_timestamp_nanos(secs, dur.subsec_nanos())
            }
            Err(err) => {
                let dur = err.duration();
                let secs = i64::try_from(dur.as_secs()).map_err(|_| TimestampError::OutOfRange)?;
                let subsec = dur.subsec_nanos();
                if subsec == 0 {
                    let neg_secs = secs.checked_neg().ok_or(TimestampError::OutOfRange)?;
                    Self::from_unix_timestamp_nanos(neg_secs, 0)
                } else {
                    let neg_secs = secs
                        .checked_add(1)
                        .and_then(i64::checked_neg)
                        .ok_or(TimestampError::OutOfRange)?;
                    Self::from_unix_timestamp_nanos(neg_secs, 1_000_000_000 - subsec)
                }
            }
        }
    }

    /// Whole seconds since `1970-01-01T00:00:00Z`.
    #[inline]
    pub const fn unix_timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Total nanoseconds since `1970-01-01T00:00:00Z`.
    #[inline]
    pub const fn unix_timestamp_nanos(&self) -> i128 {
        self.0.unix_timestamp_nanos()
    }

    /// Nanoseconds past the whole second (`0..1_000_000_000`).
    #[inline]
    pub const fn subsec_nanos(&self) -> u32 {
        self.0.nanosecond()
    }

    /// UTC calendar date.
    #[inline]
    pub const fn date(&self) -> Date {
        self.0.date()
    }

    /// UTC time-of-day.
    #[inline]
    pub const fn time(&self) -> Time {
        self.0.time()
    }

    /// Add a signed duration, returning `None` on overflow.
    #[inline]
    pub fn checked_add(self, duration: SignedDuration) -> Option<Self> {
        self.0
            .checked_add(duration)
            .and_then(|dt| Self::from_validated_utc(dt).ok())
    }

    /// Subtract a signed duration, returning `None` on overflow.
    #[inline]
    pub fn checked_sub(self, duration: SignedDuration) -> Option<Self> {
        self.0
            .checked_sub(duration)
            .and_then(|dt| Self::from_validated_utc(dt).ok())
    }

    /// Format as RFC 3339 with `SecondsFormat::AutoSi` and `+00:00`, matching
    /// `chrono::DateTime<Utc>::to_rfc3339()` byte-for-byte.
    pub fn to_rfc3339(&self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }

    /// Format as RFC 3339 with `SecondsFormat::AutoSi` and `Z`, matching
    /// `chrono::DateTime<Utc>`'s serde serialization byte-for-byte.
    pub fn to_rfc3339_z(&self) -> String {
        self.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    }

    /// Format as RFC 3339 with explicit precision and `Z` vs `+00:00` choice,
    /// matching `chrono::DateTime<Utc>::to_rfc3339_opts(secform, use_z)`
    /// byte-for-byte.
    pub fn to_rfc3339_opts(&self, secform: SecondsFormat, use_z: bool) -> String {
        // Max RFC 3339 UTC string is 36 bytes (extended signed year + nanos + "+00:00").
        let mut out = String::with_capacity(36);
        let _ = self.write_rfc3339_opts(&mut out, secform, use_z);
        out
    }

    /// Write RFC 3339 output into any [`fmt::Write`] without allocating.
    pub fn write_rfc3339_opts(
        &self,
        f: &mut impl fmt::Write,
        secform: SecondsFormat,
        use_z: bool,
    ) -> fmt::Result {
        let dt = self.0;
        let year = dt.year();
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}")?;
        } else {
            write!(f, "{year:+05}")?;
        }

        write!(
            f,
            "-{:02}-{:02}T{:02}:{:02}:{:02}",
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        )?;

        let nano = dt.nanosecond();
        match secform {
            SecondsFormat::Secs => {}
            SecondsFormat::Millis => write!(f, ".{:03}", nano / 1_000_000)?,
            SecondsFormat::Micros => write!(f, ".{:06}", nano / 1_000)?,
            SecondsFormat::Nanos => write!(f, ".{nano:09}")?,
            SecondsFormat::AutoSi => {
                if nano == 0 {
                    // Whole second: omit fractional part.
                } else if nano.is_multiple_of(1_000_000) {
                    write!(f, ".{:03}", nano / 1_000_000)?;
                } else if nano.is_multiple_of(1_000) {
                    write!(f, ".{:06}", nano / 1_000)?;
                } else {
                    write!(f, ".{nano:09}")?;
                }
            }
        }

        if use_z {
            f.write_str("Z")
        } else {
            f.write_str("+00:00")
        }
    }

    /// Format as RFC 2822 (`Thu, 14 May 2026 10:00:00 +0000`), matching
    /// `chrono::DateTime<Utc>::to_rfc2822()` byte-for-byte: English short
    /// weekday and month names, an unpadded day of month, a four-digit year,
    /// whole seconds and a `+0000` offset.
    ///
    /// Returns `None` for years outside `0..=9999`, which RFC 2822 cannot
    /// represent and where chrono's formatter panics instead.
    pub fn to_rfc2822(&self) -> Option<String> {
        const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let dt = self.0;
        let year = dt.year();
        if !(0..=9999).contains(&year) {
            return None;
        }
        let weekday = WEEKDAYS.get(usize::from(dt.weekday().number_days_from_sunday()))?;
        let month = MONTHS.get(usize::from(u8::from(dt.month())).checked_sub(1)?)?;
        Some(format!(
            "{weekday}, {} {month} {year:04} {:02}:{:02}:{:02} +0000",
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        ))
    }

    /// Parse a strict RFC 3339 timestamp string and normalize it to UTC.
    #[inline]
    pub fn parse_from_rfc3339(s: &str) -> Result<Self, TimestampError> {
        parse_rfc3339(s)
    }

    /// Compute the signed microseconds since the PostgreSQL epoch
    /// (`2000-01-01T00:00:00Z`), truncating sub-microsecond nanoseconds toward
    /// zero identically to `sqlx-postgres`'s `chrono::DateTime<Utc>` encoder.
    pub fn to_postgres_micros(&self) -> Result<i64, TimestampError> {
        i64::try_from((self.0 - POSTGRES_EPOCH).whole_microseconds())
            .map_err(|_| TimestampError::OutOfRange)
    }

    /// Construct from PostgreSQL binary `TIMESTAMPTZ` / `TIMESTAMP`
    /// microseconds since `2000-01-01T00:00:00Z`.
    pub fn from_postgres_micros(micros: i64) -> Result<Self, TimestampError> {
        let dt = POSTGRES_EPOCH
            .checked_add(SignedDuration::microseconds(micros))
            .ok_or(TimestampError::OutOfRange)?;
        Self::from_validated_utc(dt)
    }

    /// Decode a PostgreSQL binary `TIMESTAMPTZ` / `TIMESTAMP` payload (8-byte
    /// big-endian signed microseconds since `2000-01-01T00:00:00Z`).
    pub fn decode_postgres_binary(buf: &[u8]) -> Result<Self, TimestampError> {
        let bytes: [u8; 8] = buf.try_into().map_err(|_| TimestampError::InvalidFormat)?;
        Self::from_postgres_micros(i64::from_be_bytes(bytes))
    }

    /// Encode this timestamp into MySQL's length-prefixed binary `TIMESTAMP` /
    /// `DATETIME` wire format, matching `sqlx-mysql`'s `chrono::DateTime<Utc>`
    /// encoder byte-for-byte.
    pub fn encode_mysql_binary(&self, buf: &mut Vec<u8>) -> Result<(), TimestampError> {
        let dt = self.0;
        let year = u16::try_from(dt.year()).map_err(|_| TimestampError::OutOfRange)?;
        let len = self.mysql_binary_encoded_len();

        buf.push(len);
        buf.extend_from_slice(&year.to_le_bytes());
        buf.push(u8::from(dt.month()));
        buf.push(dt.day());

        if len > 4 {
            buf.push(dt.hour());
            buf.push(dt.minute());
            buf.push(dt.second());

            if len > 7 {
                let micros = dt.nanosecond() / 1_000;
                buf.extend_from_slice(&micros.to_le_bytes());
            }
        }

        Ok(())
    }

    /// Decode a MySQL length-prefixed binary `TIMESTAMP` / `DATETIME` payload.
    pub fn decode_mysql_binary(buf: &[u8]) -> Result<Self, TimestampError> {
        if buf.is_empty() {
            return Err(TimestampError::InvalidFormat);
        }
        let len = usize::from(buf[0]);
        let payload = &buf[1..];

        if len < 4 || payload.len() < len {
            return Err(TimestampError::InvalidFormat);
        }

        let year = i32::from(u16::from_le_bytes([payload[0], payload[1]]));
        if year > MAX_SUPPORTED_YEAR {
            return Err(TimestampError::OutOfRange);
        }
        let month = Month::try_from(payload[2]).map_err(|_| TimestampError::InvalidComponent)?;
        let day = payload[3];
        let date = Date::from_calendar_date(year, month, day)
            .map_err(|_| TimestampError::InvalidComponent)?;

        let time = if len == 4 {
            Time::MIDNIGHT
        } else if (7..=11).contains(&len) {
            let hour = payload[4];
            let minute = payload[5];
            let second = payload[6];
            let micros = if len > 7 {
                let mut raw = [0u8; 4];
                let micro_len = len - 7;
                raw[..micro_len].copy_from_slice(&payload[7..7 + micro_len]);
                u32::from_le_bytes(raw)
            } else {
                0
            };
            Time::from_hms_micro(hour, minute, second, micros)
                .map_err(|_| TimestampError::InvalidComponent)?
        } else {
            return Err(TimestampError::InvalidFormat);
        };

        Self::from_validated_utc(PlainDateTime::new(date, time).assume_utc())
    }

    #[inline]
    fn mysql_binary_encoded_len(&self) -> u8 {
        let dt = self.0;
        match (dt.hour(), dt.minute(), dt.second(), dt.nanosecond()) {
            (0, 0, 0, 0) => 4,
            (_, _, _, 0) => 7,
            (_, _, _, _) => 11,
        }
    }
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc3339_opts(f, SecondsFormat::AutoSi, true)
    }
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_rfc3339_opts(f, SecondsFormat::AutoSi, true)
    }
}

impl FromStr for UtcTimestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_rfc3339(s)
    }
}

impl TryFrom<OffsetDateTime> for UtcTimestamp {
    type Error = TimestampError;

    fn try_from(dt: OffsetDateTime) -> Result<Self, Self::Error> {
        Self::try_from_offset_date_time(dt)
    }
}

impl From<UtcTimestamp> for OffsetDateTime {
    fn from(ts: UtcTimestamp) -> Self {
        ts.0
    }
}

impl Sub for UtcTimestamp {
    type Output = SignedDuration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0 - rhs.0
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        struct FormatRfc3339Z(UtcTimestamp);

        impl fmt::Display for FormatRfc3339Z {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.write_rfc3339_opts(f, SecondsFormat::AutoSi, true)
            }
        }

        serializer.collect_str(&FormatRfc3339Z(*self))
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UtcTimestampVisitor;

        impl de::Visitor<'_> for UtcTimestampVisitor {
            type Value = UtcTimestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RFC 3339 formatted date and time string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_rfc3339(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(UtcTimestampVisitor)
    }
}

// ── Parsing helpers ────────────────────────────────────────────────────────

/// Parse a strict RFC 3339 timestamp string (requiring `Z`/`z` or `±HH:MM`)
/// and normalize it to UTC.
pub fn parse_rfc3339(s: &str) -> Result<UtcTimestamp, TimestampError> {
    let (date, rest) = parse_date(s.as_bytes())?;
    let rest = match rest.first().copied() {
        Some(b'T' | b't' | b' ') => &rest[1..],
        _ => return Err(TimestampError::InvalidFormat),
    };
    let (time, rest) = parse_hms_required(rest)?;
    let (offset, rest) = parse_rfc3339_offset(rest)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    assemble_utc(date, time, offset)
}

/// Parse any SQL text timestamp format accepted by `sqlx-sqlite`'s `chrono`
/// decoder and Ferrum's legacy `CURRENT_TIMESTAMP` rows:
///
/// - Full RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.f...](Z|±HH:MM)`)
/// - Space- or `T`-separated timestamps with optional seconds, optional
///   fractional seconds, and optional offset (`Z`, `±HH`, `±HHMM`, `±HH:MM`,
///   `±HH:MM:SS`; missing offset is interpreted as UTC).
pub fn parse_sqlite_datetime_text(s: &str) -> Result<UtcTimestamp, TimestampError> {
    if let Ok(ts) = parse_rfc3339(s) {
        return Ok(ts);
    }
    parse_flexible_sql_datetime(s)
}

/// Parse a PostgreSQL text-protocol `TIMESTAMPTZ` / `TIMESTAMP` string
/// (e.g. `2026-01-02 03:04:05+00`, `2026-01-02 03:04:05.123456-05:30`,
/// `2026-01-02 03:04:05.123456+05:30:15`, or `2026-01-02 03:04:05`) and
/// normalize it to UTC.
pub fn parse_postgres_datetime_text(s: &str) -> Result<UtcTimestamp, TimestampError> {
    let (date, rest) = parse_date(s.as_bytes())?;
    let rest = match rest.first().copied() {
        Some(b' ' | b'T' | b't') => &rest[1..],
        _ => return Err(TimestampError::InvalidFormat),
    };
    let (time, rest) = parse_hms_required(rest)?;
    let (offset, rest) = parse_optional_sql_offset(rest)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    assemble_utc(date, time, offset)
}

/// Parse a MySQL text-protocol `DATETIME` / `TIMESTAMP` string
/// (`YYYY-MM-DD HH:MM:SS[.f...]`, assumed UTC) or legacy RFC 3339 string.
pub fn parse_mysql_datetime_text(s: &str) -> Result<UtcTimestamp, TimestampError> {
    if let Ok(ts) = parse_rfc3339(s) {
        return Ok(ts);
    }
    let (date, rest) = parse_date(s.as_bytes())?;
    let rest = rest
        .strip_prefix(b" ")
        .ok_or(TimestampError::InvalidFormat)?;
    let (time, rest) = parse_hms_required(rest)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    assemble_utc(date, time, UtcOffset::UTC)
}

fn parse_flexible_sql_datetime(s: &str) -> Result<UtcTimestamp, TimestampError> {
    let (date, rest) = parse_date(s.as_bytes())?;
    let rest = match rest.first().copied() {
        Some(b' ' | b'T' | b't') => &rest[1..],
        _ => return Err(TimestampError::InvalidFormat),
    };
    let (time, rest) = parse_hm_or_hms(rest)?;
    let (offset, rest) = parse_optional_sql_offset(rest)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    assemble_utc(date, time, offset)
}

fn assemble_utc(date: Date, time: Time, offset: UtcOffset) -> Result<UtcTimestamp, TimestampError> {
    let dt = PlainDateTime::new(date, time).assume_offset(offset);
    UtcTimestamp::try_from_offset_date_time(dt)
}

fn parse_date(bytes: &[u8]) -> Result<(Date, &[u8]), TimestampError> {
    let (year, rest) = match bytes.first().copied() {
        Some(sign @ (b'+' | b'-')) => {
            let mut rest = &bytes[1..];
            let digit_count = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            if !(4..=6).contains(&digit_count) {
                return Err(TimestampError::InvalidFormat);
            }
            let mut acc: i32 = 0;
            for &b in &rest[..digit_count] {
                acc = acc
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(i32::from(b - b'0')))
                    .ok_or(TimestampError::OutOfRange)?;
            }
            rest = &rest[digit_count..];
            let signed = if sign == b'-' {
                acc.checked_neg().ok_or(TimestampError::OutOfRange)?
            } else {
                acc
            };
            (signed, rest)
        }
        _ => {
            let (y, rest) = parse_4_digits(bytes)?;
            (i32::from(y), rest)
        }
    };

    let rest = rest
        .strip_prefix(b"-")
        .ok_or(TimestampError::InvalidFormat)?;
    let (month_raw, rest) = parse_2_digits(rest)?;
    let rest = rest
        .strip_prefix(b"-")
        .ok_or(TimestampError::InvalidFormat)?;
    let (day, rest) = parse_2_digits(rest)?;

    let month = Month::try_from(month_raw).map_err(|_| TimestampError::InvalidComponent)?;
    let date =
        Date::from_calendar_date(year, month, day).map_err(|_| TimestampError::InvalidComponent)?;
    Ok((date, rest))
}

fn parse_hms_required(bytes: &[u8]) -> Result<(Time, &[u8]), TimestampError> {
    let (hour, rest) = parse_2_digits(bytes)?;
    let rest = rest
        .strip_prefix(b":")
        .ok_or(TimestampError::InvalidFormat)?;
    let (minute, rest) = parse_2_digits(rest)?;
    let rest = rest
        .strip_prefix(b":")
        .ok_or(TimestampError::InvalidFormat)?;
    let (second, rest) = parse_2_digits(rest)?;
    let (nanos, rest) = parse_optional_fraction_nanos(rest)?;
    let time = Time::from_hms_nano(hour, minute, second, nanos)
        .map_err(|_| TimestampError::InvalidComponent)?;
    Ok((time, rest))
}

fn parse_hm_or_hms(bytes: &[u8]) -> Result<(Time, &[u8]), TimestampError> {
    let (hour, rest) = parse_2_digits(bytes)?;
    let rest = rest
        .strip_prefix(b":")
        .ok_or(TimestampError::InvalidFormat)?;
    let (minute, rest) = parse_2_digits(rest)?;
    let (second, nanos, rest) = if let Some(after_colon) = rest.strip_prefix(b":") {
        let (second, rest) = parse_2_digits(after_colon)?;
        let (nanos, rest) = parse_optional_fraction_nanos(rest)?;
        (second, nanos, rest)
    } else {
        (0, 0, rest)
    };
    let time = Time::from_hms_nano(hour, minute, second, nanos)
        .map_err(|_| TimestampError::InvalidComponent)?;
    Ok((time, rest))
}

fn parse_optional_fraction_nanos(bytes: &[u8]) -> Result<(u32, &[u8]), TimestampError> {
    let Some(rest) = bytes.strip_prefix(b".") else {
        return Ok((0, bytes));
    };
    let digit_count = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if digit_count == 0 {
        return Err(TimestampError::InvalidFormat);
    }
    let used = digit_count.min(9);
    let mut nanos: u32 = 0;
    for &b in &rest[..used] {
        nanos = nanos * 10 + u32::from(b - b'0');
    }
    for _ in used..9 {
        nanos *= 10;
    }
    Ok((nanos, &rest[digit_count..]))
}

fn parse_rfc3339_offset(bytes: &[u8]) -> Result<(UtcOffset, &[u8]), TimestampError> {
    match bytes.first().copied() {
        Some(b'Z' | b'z') => Ok((UtcOffset::UTC, &bytes[1..])),
        Some(sign @ (b'+' | b'-')) => {
            let (hour, rest) = parse_2_digits(&bytes[1..])?;
            let rest = rest
                .strip_prefix(b":")
                .ok_or(TimestampError::InvalidFormat)?;
            let (minute, rest) = parse_2_digits(rest)?;
            let offset = build_utc_offset(sign == b'-', hour, minute, 0)?;
            Ok((offset, rest))
        }
        _ => Err(TimestampError::InvalidFormat),
    }
}

fn parse_optional_sql_offset(bytes: &[u8]) -> Result<(UtcOffset, &[u8]), TimestampError> {
    match bytes.first().copied() {
        None => Ok((UtcOffset::UTC, bytes)),
        Some(b'Z' | b'z') => Ok((UtcOffset::UTC, &bytes[1..])),
        Some(sign @ (b'+' | b'-')) => {
            let negative = sign == b'-';
            let (hour, rest) = parse_2_digits(&bytes[1..])?;
            let (minute, second, rest) = if let Some(after_colon) = rest.strip_prefix(b":") {
                let (minute, rest) = parse_2_digits(after_colon)?;
                if let Some(after_sec_colon) = rest.strip_prefix(b":") {
                    let (second, rest) = parse_2_digits(after_sec_colon)?;
                    (minute, second, rest)
                } else {
                    (minute, 0, rest)
                }
            } else if rest.len() >= 2 && rest[0].is_ascii_digit() && rest[1].is_ascii_digit() {
                let (minute, rest) = parse_2_digits(rest)?;
                (minute, 0, rest)
            } else {
                (0, 0, rest)
            };
            let offset = build_utc_offset(negative, hour, minute, second)?;
            Ok((offset, rest))
        }
        _ => Err(TimestampError::InvalidFormat),
    }
}

fn build_utc_offset(
    negative: bool,
    hour: u8,
    minute: u8,
    second: u8,
) -> Result<UtcOffset, TimestampError> {
    if hour > 23 || minute > 59 || second > 59 {
        return Err(TimestampError::InvalidComponent);
    }
    let (h, m, s) = if negative {
        (-(hour as i8), -(minute as i8), -(second as i8))
    } else {
        (hour as i8, minute as i8, second as i8)
    };
    UtcOffset::from_hms(h, m, s).map_err(|_| TimestampError::InvalidComponent)
}

fn parse_2_digits(bytes: &[u8]) -> Result<(u8, &[u8]), TimestampError> {
    if bytes.len() < 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return Err(TimestampError::InvalidFormat);
    }
    let value = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    Ok((value, &bytes[2..]))
}

fn parse_4_digits(bytes: &[u8]) -> Result<(u16, &[u8]), TimestampError> {
    if bytes.len() < 4 || !bytes[..4].iter().all(u8::is_ascii_digit) {
        return Err(TimestampError::InvalidFormat);
    }
    let value = u16::from(bytes[0] - b'0') * 1_000
        + u16::from(bytes[1] - b'0') * 100
        + u16::from(bytes[2] - b'0') * 10
        + u16::from(bytes[3] - b'0');
    Ok((value, &bytes[4..]))
}

/// Convert a SQLite Julian day `REAL` value to UTC, using `floor()` so
/// pre-epoch sub-second values retain the right sign (matching `sqlx-sqlite`
/// 0.9.1's `chrono` decoder).
pub fn decode_sqlite_julian_day(value: f64) -> Result<UtcTimestamp, TimestampError> {
    const EPOCH_IN_JULIAN_DAYS: f64 = 2_440_587.5;
    const SECONDS_IN_DAY: f64 = 86_400.0;

    let timestamp = (value - EPOCH_IN_JULIAN_DAYS) * SECONDS_IN_DAY;
    if !timestamp.is_finite() {
        return Err(TimestampError::OutOfRange);
    }

    let seconds = timestamp.floor();
    let raw_nanos = ((timestamp - seconds) * 1e9) as u32;
    let whole_secs = seconds as i64;
    let (secs, nanos) = if raw_nanos >= 1_000_000_000 {
        (
            whole_secs
                .checked_add(1)
                .ok_or(TimestampError::OutOfRange)?,
            raw_nanos - 1_000_000_000,
        )
    } else {
        (whole_secs, raw_nanos)
    };

    UtcTimestamp::from_unix_timestamp_nanos(secs, nanos)
}

// ── SQLx implementations: SQLite ───────────────────────────────────────────

impl Type<Sqlite> for UtcTimestamp {
    fn type_info() -> SqliteTypeInfo {
        <OffsetDateTime as Type<Sqlite>>::type_info()
    }

    fn compatible(ty: &SqliteTypeInfo) -> bool {
        // Matches `sqlx-sqlite`'s `chrono::DateTime<Utc>`: Datetime, Text,
        // Integer/Int4 (Unix seconds), and Float (Julian day).
        matches!(ty.name(), "DATETIME" | "TEXT" | "INTEGER" | "REAL")
    }
}

impl Encode<'_, Sqlite> for UtcTimestamp {
    fn encode_by_ref(&self, buf: &mut SqliteArgumentsBuffer) -> Result<IsNull, BoxDynError> {
        // `chrono::DateTime<Utc>` on SQLite writes RFC 3339 with AutoSi and `+00:00`.
        <String as Encode<'_, Sqlite>>::encode(self.to_rfc3339(), buf)
    }
}

impl<'r> Decode<'r, Sqlite> for UtcTimestamp {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        enum SqliteColumnKind {
            Text,
            Integer,
            Float,
            Other,
        }

        let kind = match value.type_info().name() {
            "TEXT" | "DATETIME" => SqliteColumnKind::Text,
            "INTEGER" => SqliteColumnKind::Integer,
            "REAL" => SqliteColumnKind::Float,
            _ => SqliteColumnKind::Other,
        };

        match kind {
            SqliteColumnKind::Text => {
                let raw = <&str as Decode<'r, Sqlite>>::decode(value)?;
                parse_sqlite_datetime_text(raw).map_err(Into::into)
            }
            SqliteColumnKind::Integer => {
                let secs = <i64 as Decode<'r, Sqlite>>::decode(value)?;
                Self::from_unix_timestamp(secs).map_err(Into::into)
            }
            SqliteColumnKind::Float => {
                let julian = <f64 as Decode<'r, Sqlite>>::decode(value)?;
                decode_sqlite_julian_day(julian).map_err(Into::into)
            }
            SqliteColumnKind::Other => Err(format!(
                "unsupported SQLite datetime column type: {}",
                value.type_info()
            )
            .into()),
        }
    }
}

// ── SQLx implementations: MySQL ────────────────────────────────────────────

impl Type<MySql> for UtcTimestamp {
    fn type_info() -> MySqlTypeInfo {
        <OffsetDateTime as Type<MySql>>::type_info()
    }

    fn compatible(ty: &MySqlTypeInfo) -> bool {
        <OffsetDateTime as Type<MySql>>::compatible(ty) || <&str as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for UtcTimestamp {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        self.encode_mysql_binary(buf)?;
        Ok(IsNull::No)
    }

    fn size_hint(&self) -> usize {
        // Match `sqlx-mysql`'s `Encode<MySql> for chrono::DateTime<Utc>`, which
        // uses `Encode::size_hint`'s default `mem::size_of_val(self)` (12 bytes,
        // matching the maximum 1-byte length prefix + 11-byte binary wire form).
        12
    }
}

impl<'r> Decode<'r, MySql> for UtcTimestamp {
    fn decode(value: MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
        let is_native_datetime = <OffsetDateTime as Type<MySql>>::compatible(&value.type_info());
        if is_native_datetime {
            let dt = <OffsetDateTime as Decode<'r, MySql>>::decode(value)?;
            Self::try_from_offset_date_time(dt).map_err(Into::into)
        } else {
            let raw = <&str as Decode<'r, MySql>>::decode(value)?;
            parse_sqlite_datetime_text(raw).map_err(Into::into)
        }
    }
}

// ── SQLx implementations: PostgreSQL ───────────────────────────────────────

impl Type<Postgres> for UtcTimestamp {
    fn type_info() -> PgTypeInfo {
        <OffsetDateTime as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <OffsetDateTime as Type<Postgres>>::compatible(ty)
            || ty.name() == "TIMESTAMP"
            || <&str as Type<Postgres>>::compatible(ty)
    }
}

impl PgHasArrayType for UtcTimestamp {
    fn array_type_info() -> PgTypeInfo {
        <OffsetDateTime as PgHasArrayType>::array_type_info()
    }
}

impl Encode<'_, Postgres> for UtcTimestamp {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let micros = self.to_postgres_micros()?;
        <i64 as Encode<'_, Postgres>>::encode(micros, buf)
    }

    fn size_hint(&self) -> usize {
        std::mem::size_of::<i64>()
    }
}

impl<'r> Decode<'r, Postgres> for UtcTimestamp {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let is_text_column = <&str as Type<Postgres>>::compatible(&value.type_info());
        if is_text_column {
            let raw = value.as_str()?;
            return parse_sqlite_datetime_text(raw).map_err(Into::into);
        }

        match value.format() {
            PgValueFormat::Binary => {
                let micros = <i64 as Decode<'r, Postgres>>::decode(value)?;
                Self::from_postgres_micros(micros).map_err(Into::into)
            }
            PgValueFormat::Text => {
                let raw = value.as_str()?;
                parse_postgres_datetime_text(raw).map_err(Into::into)
            }
        }
    }
}

// ── SQLx implementations: Any ──────────────────────────────────────────────

impl Type<Any> for UtcTimestamp {
    fn type_info() -> AnyTypeInfo {
        <String as Type<Any>>::type_info()
    }

    fn compatible(ty: &AnyTypeInfo) -> bool {
        <String as Type<Any>>::compatible(ty)
    }
}

impl Encode<'_, Any> for UtcTimestamp {
    fn encode_by_ref(
        &self,
        buf: &mut <Any as Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        <String as Encode<'_, Any>>::encode(self.to_rfc3339(), buf)
    }
}

impl<'r> Decode<'r, Any> for UtcTimestamp {
    fn decode(value: <Any as Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        let raw = <&str as Decode<'r, Any>>::decode(value)?;
        parse_sqlite_datetime_text(raw).map_err(Into::into)
    }
}
