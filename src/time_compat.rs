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
///
/// # Leap seconds (issue #7419 owner decision)
///
/// chrono's `DateTime<Utc>` can hold a leap second (`23:59:60.f`, stored as
/// second 59 with a sub-second part of `1_000_000_000 + f`); `UtcTimestamp`
/// cannot. The chrono-compatible parsers accept `:60` exactly as chrono does,
/// and [`ChronoParsedDateTime::to_utc_timestamp`] stores it as the
/// next-second instant chrono's `timestamp_nanos_opt()` reports (`:00.f` of
/// the following minute). As a result:
///
/// - Unix nanoseconds and milliseconds equal chrono's `timestamp_nanos_opt()`
///   and `timestamp_millis()` for the same input, and values order by those
///   nanoseconds.
/// - Known, accepted differences for leap-second inputs only:
///   - Formatting prints `:00.f` of the next minute instead of chrono's `:60.f`.
///   - `unix_timestamp()` is one more than chrono's `timestamp()`, which
///     reports the `:59` second.
///   - chrono orders a leap second before every instant of the following
///     second; here it sorts at `:00.f`.
///
/// Every non-leap value is unaffected, so database text and other encodings
/// stay byte-identical.
///
/// # Years outside `-9999..=9999` (issue #7419 owner decision)
///
/// chrono's `DateTime<Utc>` spans years `-262143..=262142`; `UtcTimestamp`
/// does not, and does not rely on `time`'s `large-dates` feature. The
/// chrono-compatible parsers still accept exactly what chrono accepts (for
/// example `9999-12-31T23:30:00-01:00`, an RFC 2822 date in year 12345, or
/// the relaxed `+12345-01-01T00:00:00Z`), but converting a value whose UTC
/// instant falls outside this range fails with
/// [`TimestampError::OutOfRange`]. Each call site reports that as its normal
/// parse or validation error; nothing is clamped. Values inside the range are
/// unaffected.
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

    /// `1970-01-01T00:00:00Z`, matching `chrono::DateTime::<Utc>::UNIX_EPOCH`.
    pub const UNIX_EPOCH: Self = Self(OffsetDateTime::UNIX_EPOCH);

    /// Construct from Unix epoch milliseconds, flooring toward negative
    /// infinity like `chrono::DateTime::from_timestamp_millis`. Fails with
    /// [`TimestampError::OutOfRange`] outside the supported year range.
    pub fn from_unix_timestamp_millis(millis: i64) -> Result<Self, TimestampError> {
        let secs = millis.div_euclid(1_000);
        let nanos = u32::try_from(millis.rem_euclid(1_000) * 1_000_000)
            .map_err(|_| TimestampError::OutOfRange)?;
        Self::from_unix_timestamp_nanos(secs, nanos)
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

    /// Whole milliseconds since `1970-01-01T00:00:00Z`, rounded toward
    /// negative infinity (so `1969-12-31T23:59:59.9995Z` is `-1`), matching
    /// `chrono::DateTime<Utc>::timestamp_millis()`.
    #[inline]
    pub fn unix_timestamp_millis(&self) -> i64 {
        // `unix_timestamp()` already floors toward negative infinity and
        // `millisecond()` is the non-negative millisecond within that second.
        // The supported `-9999..=9999` year range keeps the product far
        // inside `i64`.
        self.0.unix_timestamp() * 1_000 + i64::from(self.0.millisecond())
    }

    /// Format as compact `YYYYMMDD`, matching chrono's
    /// `format("%Y%m%d")` byte-for-byte (including chrono's explicit sign on
    /// years outside `0..=9999`).
    pub fn to_compact_date(&self) -> String {
        let mut out = String::with_capacity(9);
        let _ = self.write_compact_date(&mut out);
        out
    }

    /// Format as compact `YYYYMMDDHHMMSS`, matching chrono's
    /// `format("%Y%m%d%H%M%S")` byte-for-byte (including chrono's explicit
    /// sign on years outside `0..=9999`).
    pub fn to_compact_date_time(&self) -> String {
        let mut out = String::with_capacity(15);
        let _ = self.write_compact_date_time(&mut out);
        out
    }

    fn write_compact_date_time(&self, f: &mut impl fmt::Write) -> fmt::Result {
        self.write_compact_date(f)?;
        let dt = self.0;
        write!(f, "{:02}{:02}{:02}", dt.hour(), dt.minute(), dt.second())
    }

    fn write_compact_date(&self, f: &mut impl fmt::Write) -> fmt::Result {
        let dt = self.0;
        let year = dt.year();
        if (0..=9999).contains(&year) {
            write!(f, "{year:04}")?;
        } else {
            write!(f, "{year:+05}")?;
        }
        write!(f, "{:02}{:02}", u8::from(dt.month()), dt.day())
    }

    /// Format as `%d/%b/%Y:%H:%M:%S %z` (`27/Nov/2026:10:20:30 +0000`, the
    /// Apache common-log / API Gateway `requestContext.time` shape), matching
    /// chrono's strftime output byte-for-byte for a UTC value, including
    /// chrono's explicit `%Y` sign outside `0..=9999`.
    pub fn to_common_log_format(&self) -> String {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let dt = self.0;
        let month = usize::from(u8::from(dt.month()))
            .checked_sub(1)
            .and_then(|index| MONTHS.get(index))
            .copied()
            .unwrap_or("Jan");
        let year = dt.year();
        let year = if (0..=9999).contains(&year) {
            format!("{year:04}")
        } else {
            format!("{year:+05}")
        };
        format!(
            "{:02}/{month}/{year}:{:02}:{:02}:{:02} +0000",
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
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

/// Parses exactly what chrono's `DateTime<Utc>: FromStr` (the relaxed RFC 3339
/// parser) accepts, normalizing a leap second and refusing an instant outside
/// the supported year range (issue #7419 owner decisions).
impl FromStr for UtcTimestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_rfc3339_relaxed_chrono(s).and_then(|parsed| parsed.to_utc_timestamp())
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
                // Same acceptance as chrono's `DateTime<Utc>` serde impl,
                // which parses with the relaxed RFC 3339 parser (issue #7419).
                value.parse::<UtcTimestamp>().map_err(E::custom)
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

// ── chrono-compatible parsers ──────────────────────────────────────────────
//
// Issue #7419 owner decision: every parse site that moves off chrono must
// accept and reject exactly the inputs chrono 0.4.45 does, and produce the
// same value. The functions below are line-for-line ports of chrono's
// `parse_from_rfc3339`, `DateTime<FixedOffset>: FromStr` (the parser behind
// chrono's serde `Deserialize`), `parse_from_rfc2822`, and the
// `DateTime::parse_from_str` / `NaiveDateTime::parse_from_str` strftime
// engine for the specifiers Ferrum uses. `tests/unit/config/
// time_compat_chrono_parse_tests.rs` runs an accept/reject corpus through
// both implementations.

/// chrono's `NaiveDate` year bounds (`MIN_YEAR`/`MAX_YEAR` in chrono 0.4.45).
const CHRONO_MIN_YEAR: i32 = (i32::MIN >> 13) + 1;
const CHRONO_MAX_YEAR: i32 = (i32::MAX >> 13) - 1;

/// A date-time accepted by one of the chrono-compatible parsers.
///
/// Like `chrono::DateTime<FixedOffset>`, it holds the local (offset-applied)
/// calendar and clock fields plus the fixed UTC offset. A leap second (`:60`)
/// is kept the way chrono keeps it: second `59` with a sub-second part of
/// `1_000_000_000 + fraction`. Years span chrono's full `-262143..=262142`
/// range, which is wider than [`UtcTimestamp`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChronoParsedDateTime {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
    offset_seconds: i32,
}

impl ChronoParsedDateTime {
    /// Local calendar year (chrono `naive_local().year()`).
    pub const fn year(&self) -> i32 {
        self.year
    }

    /// Local month, `1..=12`.
    pub const fn month(&self) -> u8 {
        self.month
    }

    /// Local day of month, `1..=31`.
    pub const fn day(&self) -> u8 {
        self.day
    }

    /// Local hour, `0..=23`.
    pub const fn hour(&self) -> u8 {
        self.hour
    }

    /// Local minute, `0..=59`.
    pub const fn minute(&self) -> u8 {
        self.minute
    }

    /// Local second, `0..=59` (a leap second reports `59`, as in chrono).
    pub const fn second(&self) -> u8 {
        self.second
    }

    /// Sub-second nanoseconds, `>= 1_000_000_000` for a leap second, exactly
    /// like chrono's `nanosecond()` / `timestamp_subsec_nanos()`.
    pub const fn nanosecond(&self) -> u32 {
        self.nanosecond
    }

    /// Fixed offset east of UTC in seconds (chrono `offset().local_minus_utc()`).
    pub const fn offset_seconds(&self) -> i32 {
        self.offset_seconds
    }

    /// Whether the input named a leap second (`:60`).
    pub const fn is_leap_second(&self) -> bool {
        self.nanosecond >= 1_000_000_000
    }

    /// Whole Unix seconds, identical to chrono's `DateTime::timestamp()`.
    pub fn unix_timestamp(&self) -> i64 {
        civil_days(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
            - i64::from(self.offset_seconds)
    }

    /// Unix milliseconds, identical to chrono's `DateTime::timestamp_millis()`
    /// (for a leap second this lands in the following second, as in chrono).
    pub fn unix_timestamp_millis(&self) -> i64 {
        self.unix_timestamp() * 1_000 + i64::from(self.nanosecond / 1_000_000)
    }

    /// Unix nanoseconds, identical to chrono's `DateTime::timestamp_nanos_opt()`
    /// (including its overflow behaviour and leap-second representation).
    pub fn unix_timestamp_nanos_opt(&self) -> Option<i64> {
        let mut timestamp = self.unix_timestamp();
        let mut subsec_nanos = i64::from(self.nanosecond);
        // Same negative-timestamp rearrangement as chrono (chrono#1289).
        if timestamp < 0 {
            subsec_nanos -= 1_000_000_000;
            timestamp += 1;
        }
        timestamp
            .checked_mul(1_000_000_000)?
            .checked_add(subsec_nanos)
    }

    /// Convert to a [`UtcTimestamp`].
    ///
    /// A leap second (`:60.f`) is normalized to the next-second instant that
    /// chrono's `timestamp_nanos_opt()` reports for it (`:00.f` of the
    /// following minute), per the #7419 owner decision; see the leap-second
    /// note on [`UtcTimestamp`]. Fails with [`TimestampError::OutOfRange`]
    /// outside `UtcTimestamp`'s `-9999..=9999` year range.
    pub fn to_utc_timestamp(&self) -> Result<UtcTimestamp, TimestampError> {
        if self.is_leap_second() {
            let next_second = self
                .unix_timestamp()
                .checked_add(1)
                .ok_or(TimestampError::OutOfRange)?;
            return UtcTimestamp::from_unix_timestamp_nanos(
                next_second,
                self.nanosecond - 1_000_000_000,
            );
        }
        UtcTimestamp::from_unix_timestamp_nanos(self.unix_timestamp(), self.nanosecond)
    }
}

/// `chrono::TimeDelta::try_seconds(secs)` acceptance as a [`SignedDuration`]:
/// `Some` exactly when chrono's millisecond-bounded `TimeDelta` can represent
/// `secs` whole seconds (`|secs| <= i64::MAX / 1000`), so migrated
/// configuration bounds accept and reject the same values (issue #7419).
pub fn chrono_try_seconds(secs: i64) -> Option<SignedDuration> {
    const MAX_SECS: i64 = i64::MAX / 1_000;
    if (-MAX_SECS..=MAX_SECS).contains(&secs) {
        Some(SignedDuration::seconds(secs))
    } else {
        None
    }
}

/// Days from `1970-01-01` to a proleptic-Gregorian civil date.
fn civil_days(year: i32, month: u8, day: u8) -> i64 {
    let month = i64::from(month);
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn chrono_is_leap_year(year: i32) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// chrono `NaiveDate::from_ymd_opt` acceptance.
fn chrono_valid_ymd(year: i32, month: u32, day: u32) -> bool {
    if !(CHRONO_MIN_YEAR..=CHRONO_MAX_YEAR).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let days_in_month = match month {
        2 if chrono_is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month).contains(&day)
}

/// Weekday of a civil date, `0` = Sunday (chrono `num_days_from_sunday`).
fn chrono_weekday(year: i32, month: u8, day: u8) -> u8 {
    // 1970-01-01 was a Thursday (4).
    u8::try_from((civil_days(year, month, day) + 4).rem_euclid(7)).unwrap_or(0)
}

/// Assemble a `DateTime<FixedOffset>`-equivalent value, applying chrono's
/// `FixedOffset::east_opt` and `from_local_datetime` range checks.
fn chrono_assemble(
    (year, month, day): (i32, u32, u32),
    (hour, minute, second, nanosecond): (u32, u32, u32, u32),
    offset_seconds: i32,
) -> Result<ChronoParsedDateTime, TimestampError> {
    if !(-86_399..=86_399).contains(&offset_seconds) {
        return Err(TimestampError::OutOfRange);
    }
    let narrow = |v: u32| u8::try_from(v).map_err(|_| TimestampError::InvalidComponent);
    let parsed = ChronoParsedDateTime {
        year,
        month: narrow(month)?,
        day: narrow(day)?,
        hour: narrow(hour)?,
        minute: narrow(minute)?,
        second: narrow(second)?,
        nanosecond,
        offset_seconds,
    };
    // The UTC date must stay inside chrono's `NaiveDateTime` range.
    let utc_day = parsed.unix_timestamp().div_euclid(86_400);
    let min_day = civil_days(CHRONO_MIN_YEAR, 1, 1);
    let max_day = civil_days(CHRONO_MAX_YEAR, 12, 31);
    if !(min_day..=max_day).contains(&utc_day) {
        return Err(TimestampError::OutOfRange);
    }
    Ok(parsed)
}

/// chrono `NaiveTime::from_hms_nano_opt` acceptance (leap seconds only at `:59`).
fn chrono_valid_hms_nano(hour: u32, minute: u32, second: u32, nano: u32) -> bool {
    hour < 24
        && minute < 60
        && second < 60
        && nano < 2_000_000_000
        && (nano < 1_000_000_000 || second == 59)
}

/// Port of chrono `format::scan::number`.
fn chrono_scan_number(s: &str, min: usize, max: usize) -> Result<(&str, i64), TimestampError> {
    let bytes = s.as_bytes();
    if bytes.len() < min {
        return Err(TimestampError::InvalidFormat);
    }
    let mut n = 0i64;
    for (i, c) in bytes.iter().take(max).copied().enumerate() {
        if !c.is_ascii_digit() {
            if i < min {
                return Err(TimestampError::InvalidFormat);
            }
            return Ok((s.get(i..).ok_or(TimestampError::InvalidFormat)?, n));
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(i64::from(c - b'0')))
            .ok_or(TimestampError::OutOfRange)?;
    }
    let consumed = max.min(bytes.len());
    Ok((s.get(consumed..).ok_or(TimestampError::InvalidFormat)?, n))
}

/// Port of chrono `format::scan::nanosecond`.
fn chrono_scan_nanosecond(s: &str) -> Result<(&str, u32), TimestampError> {
    const SCALE: [u32; 10] = [
        0,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10_000,
        1_000,
        100,
        10,
        1,
    ];
    let original_len = s.len();
    let (rest, value) = chrono_scan_number(s, 1, 9)?;
    let value = u32::try_from(value).map_err(|_| TimestampError::OutOfRange)?;
    let consumed = original_len - rest.len();
    let scale = SCALE
        .get(consumed)
        .copied()
        .ok_or(TimestampError::InvalidFormat)?;
    let value = value.checked_mul(scale).ok_or(TimestampError::OutOfRange)?;
    Ok((rest.trim_start_matches(|c: char| c.is_ascii_digit()), value))
}

/// Port of chrono `format::scan::timezone_offset`.
fn chrono_scan_timezone_offset(
    mut s: &str,
    consume_colon: fn(&str) -> Result<&str, TimestampError>,
    allow_zulu: bool,
    allow_missing_minutes: bool,
    allow_tz_minus_sign: bool,
) -> Result<(&str, i32), TimestampError> {
    if allow_zulu && matches!(s.as_bytes().first(), Some(b'Z' | b'z')) {
        return Ok((s.get(1..).ok_or(TimestampError::InvalidFormat)?, 0));
    }
    let negative = match s.chars().next() {
        Some('+') => {
            s = &s['+'.len_utf8()..];
            false
        }
        Some('-') => {
            s = &s['-'.len_utf8()..];
            true
        }
        Some('\u{2212}') if allow_tz_minus_sign => {
            s = &s['\u{2212}'.len_utf8()..];
            true
        }
        _ => return Err(TimestampError::InvalidFormat),
    };
    let two = |s: &str| -> Option<(u8, u8)> {
        let b = s.as_bytes();
        Some((*b.first()?, *b.get(1)?))
    };
    let hours = match two(s) {
        Some((h1 @ b'0'..=b'9', h2 @ b'0'..=b'9')) => i32::from((h1 - b'0') * 10 + (h2 - b'0')),
        _ => return Err(TimestampError::InvalidFormat),
    };
    s = s.get(2..).ok_or(TimestampError::InvalidFormat)?;
    s = consume_colon(s)?;
    let minutes = if let Some(pair) = two(s) {
        match pair {
            (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i32::from((m1 - b'0') * 10 + (m2 - b'0')),
            (b'6'..=b'9', b'0'..=b'9') => return Err(TimestampError::OutOfRange),
            _ => return Err(TimestampError::InvalidFormat),
        }
    } else if allow_missing_minutes {
        0
    } else {
        return Err(TimestampError::InvalidFormat);
    };
    s = match s.len() {
        len if len >= 2 => s.get(2..).ok_or(TimestampError::InvalidFormat)?,
        0 => s,
        _ => return Err(TimestampError::InvalidFormat),
    };
    let seconds = hours * 3_600 + minutes * 60;
    Ok((s, if negative { -seconds } else { seconds }))
}

fn chrono_colon_required(s: &str) -> Result<&str, TimestampError> {
    s.strip_prefix(':').ok_or(TimestampError::InvalidFormat)
}

fn chrono_colon_or_space(s: &str) -> Result<&str, TimestampError> {
    Ok(s.trim_start_matches(|c: char| c == ':' || c.is_whitespace()))
}

fn chrono_no_colon(s: &str) -> Result<&str, TimestampError> {
    Ok(s)
}

/// Port of chrono `scan::short_month0` (returns `0..=11`).
fn chrono_scan_short_month0(s: &str) -> Result<(&str, u8), TimestampError> {
    let b = s.as_bytes();
    let (Some(&c0), Some(&c1), Some(&c2)) = (b.first(), b.get(1), b.get(2)) else {
        return Err(TimestampError::InvalidFormat);
    };
    let month0 = match (c0 | 32, c1 | 32, c2 | 32) {
        (b'j', b'a', b'n') => 0,
        (b'f', b'e', b'b') => 1,
        (b'm', b'a', b'r') => 2,
        (b'a', b'p', b'r') => 3,
        (b'm', b'a', b'y') => 4,
        (b'j', b'u', b'n') => 5,
        (b'j', b'u', b'l') => 6,
        (b'a', b'u', b'g') => 7,
        (b's', b'e', b'p') => 8,
        (b'o', b'c', b't') => 9,
        (b'n', b'o', b'v') => 10,
        (b'd', b'e', b'c') => 11,
        _ => return Err(TimestampError::InvalidFormat),
    };
    Ok((s.get(3..).ok_or(TimestampError::InvalidFormat)?, month0))
}

/// Port of chrono `scan::short_weekday` (returns days from Sunday).
fn chrono_scan_short_weekday(s: &str) -> Result<(&str, u8), TimestampError> {
    let b = s.as_bytes();
    let (Some(&c0), Some(&c1), Some(&c2)) = (b.first(), b.get(1), b.get(2)) else {
        return Err(TimestampError::InvalidFormat);
    };
    let weekday = match (c0 | 32, c1 | 32, c2 | 32) {
        (b's', b'u', b'n') => 0,
        (b'm', b'o', b'n') => 1,
        (b't', b'u', b'e') => 2,
        (b'w', b'e', b'd') => 3,
        (b't', b'h', b'u') => 4,
        (b'f', b'r', b'i') => 5,
        (b's', b'a', b't') => 6,
        _ => return Err(TimestampError::InvalidFormat),
    };
    Ok((s.get(3..).ok_or(TimestampError::InvalidFormat)?, weekday))
}

fn chrono_strip_suffix_ignore_case<'a>(s: &'a str, suffix: &[u8]) -> &'a str {
    let b = s.as_bytes();
    if b.len() >= suffix.len()
        && b.get(..suffix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(suffix))
    {
        s.get(suffix.len()..).unwrap_or(s)
    } else {
        s
    }
}

/// Port of chrono `scan::short_or_long_month0`.
fn chrono_scan_short_or_long_month0(s: &str) -> Result<(&str, u8), TimestampError> {
    const SUFFIXES: [&[u8]; 12] = [
        b"uary", b"ruary", b"ch", b"il", b"", b"e", b"y", b"ust", b"tember", b"ober", b"ember",
        b"ember",
    ];
    let (rest, month0) = chrono_scan_short_month0(s)?;
    let suffix = SUFFIXES
        .get(usize::from(month0))
        .ok_or(TimestampError::InvalidFormat)?;
    Ok((chrono_strip_suffix_ignore_case(rest, suffix), month0))
}

/// Port of chrono `scan::short_or_long_weekday`.
fn chrono_scan_short_or_long_weekday(s: &str) -> Result<(&str, u8), TimestampError> {
    // Indexed by days from Sunday.
    const SUFFIXES: [&[u8]; 7] = [
        b"day", b"day", b"sday", b"nesday", b"rsday", b"day", b"urday",
    ];
    let (rest, weekday) = chrono_scan_short_weekday(s)?;
    let suffix = SUFFIXES
        .get(usize::from(weekday))
        .ok_or(TimestampError::InvalidFormat)?;
    Ok((chrono_strip_suffix_ignore_case(rest, suffix), weekday))
}

/// Port of chrono `scan::space` (at least one whitespace character).
fn chrono_scan_space(s: &str) -> Result<&str, TimestampError> {
    let trimmed = s.trim_start();
    if trimmed.len() < s.len() {
        Ok(trimmed)
    } else {
        Err(TimestampError::InvalidFormat)
    }
}

/// Port of chrono `scan::timezone_offset_2822`.
fn chrono_scan_timezone_offset_2822(s: &str) -> Result<(&str, i32), TimestampError> {
    let upto = s
        .as_bytes()
        .iter()
        .position(|c| !c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    if upto == 0 {
        return chrono_scan_timezone_offset(s, chrono_no_colon, false, false, false);
    }
    let name = s
        .as_bytes()
        .get(..upto)
        .ok_or(TimestampError::InvalidFormat)?;
    let rest = s.get(upto..).ok_or(TimestampError::InvalidFormat)?;
    let hours = |h: i32| (rest, h * 3_600);
    if name.eq_ignore_ascii_case(b"gmt")
        || name.eq_ignore_ascii_case(b"ut")
        || name.eq_ignore_ascii_case(b"z")
    {
        Ok(hours(0))
    } else if name.eq_ignore_ascii_case(b"edt") {
        Ok(hours(-4))
    } else if name.eq_ignore_ascii_case(b"est") || name.eq_ignore_ascii_case(b"cdt") {
        Ok(hours(-5))
    } else if name.eq_ignore_ascii_case(b"cst") || name.eq_ignore_ascii_case(b"mdt") {
        Ok(hours(-6))
    } else if name.eq_ignore_ascii_case(b"mst") || name.eq_ignore_ascii_case(b"pdt") {
        Ok(hours(-7))
    } else if name.eq_ignore_ascii_case(b"pst") {
        Ok(hours(-8))
    } else if let [b'a'..=b'i' | b'k'..=b'y' | b'A'..=b'I' | b'K'..=b'Y'] = name {
        Ok((rest, 0))
    } else {
        Err(TimestampError::InvalidFormat)
    }
}

/// Port of chrono `scan::comment_2822`.
fn chrono_scan_comment_2822(s: &str) -> Result<&str, TimestampError> {
    enum State {
        Start,
        Next(usize),
        Escape(usize),
    }
    let s = s.trim_start();
    let mut state = State::Start;
    for (i, c) in s.bytes().enumerate() {
        state = match (state, c) {
            (State::Start, b'(') => State::Next(1),
            (State::Next(1), b')') => {
                return s.get(i + 1..).ok_or(TimestampError::InvalidFormat);
            }
            (State::Next(depth), b'\\') => State::Escape(depth),
            (State::Next(depth), b'(') => State::Next(depth + 1),
            (State::Next(depth), b')') => State::Next(depth - 1),
            (State::Next(depth), _) | (State::Escape(depth), _) => State::Next(depth),
            _ => return Err(TimestampError::InvalidFormat),
        };
    }
    Err(TimestampError::InvalidFormat)
}

/// Port of the subset of chrono's `format::Parsed` that Ferrum's formats set.
#[derive(Default)]
struct ChronoFields {
    year: Option<i32>,
    year_mod_100: Option<i32>,
    month: Option<u32>,
    day: Option<u32>,
    weekday: Option<u8>,
    hour: Option<u32>,
    minute: Option<u32>,
    second: Option<u32>,
    nanosecond: Option<u32>,
    offset: Option<i32>,
}

fn chrono_set_if_consistent<T: PartialEq>(
    slot: &mut Option<T>,
    value: T,
) -> Result<(), TimestampError> {
    match slot {
        Some(old) if *old != value => Err(TimestampError::InvalidComponent),
        _ => {
            *slot = Some(value);
            Ok(())
        }
    }
}

fn chrono_bounded(value: i64, range: std::ops::RangeInclusive<i64>) -> Result<u32, TimestampError> {
    if !range.contains(&value) {
        return Err(TimestampError::OutOfRange);
    }
    u32::try_from(value).map_err(|_| TimestampError::OutOfRange)
}

impl ChronoFields {
    fn set_year(&mut self, value: i64) -> Result<(), TimestampError> {
        let year = i32::try_from(value).map_err(|_| TimestampError::OutOfRange)?;
        chrono_set_if_consistent(&mut self.year, year)
    }

    fn set_year_mod_100(&mut self, value: i64) -> Result<(), TimestampError> {
        let value = i32::try_from(chrono_bounded(value, 0..=99)?)
            .map_err(|_| TimestampError::OutOfRange)?;
        chrono_set_if_consistent(&mut self.year_mod_100, value)
    }

    fn set_month(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.month, chrono_bounded(value, 1..=12)?)
    }

    fn set_day(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.day, chrono_bounded(value, 1..=31)?)
    }

    fn set_weekday(&mut self, days_from_sunday: u8) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.weekday, days_from_sunday)
    }

    fn set_hour(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.hour, chrono_bounded(value, 0..=23)?)
    }

    fn set_minute(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.minute, chrono_bounded(value, 0..=59)?)
    }

    fn set_second(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(&mut self.second, chrono_bounded(value, 0..=60)?)
    }

    fn set_nanosecond(&mut self, value: i64) -> Result<(), TimestampError> {
        chrono_set_if_consistent(
            &mut self.nanosecond,
            chrono_bounded(value, 0..=999_999_999)?,
        )
    }

    fn set_offset(&mut self, value: i64) -> Result<(), TimestampError> {
        let offset = i32::try_from(value).map_err(|_| TimestampError::OutOfRange)?;
        chrono_set_if_consistent(&mut self.offset, offset)
    }

    /// Port of `Parsed::to_naive_date` for year/month/day (+ weekday check).
    fn to_date(&self) -> Result<(i32, u32, u32), TimestampError> {
        let year = match (self.year, self.year_mod_100) {
            (year, None) => year,
            (Some(year), Some(rem)) => {
                if year < 0 || year % 100 != rem {
                    return Err(TimestampError::InvalidComponent);
                }
                Some(year)
            }
            (None, Some(rem)) => Some(rem + if rem < 70 { 2000 } else { 1900 }),
        };
        let (Some(year), Some(month), Some(day)) = (year, self.month, self.day) else {
            return Err(TimestampError::InvalidFormat);
        };
        if !chrono_valid_ymd(year, month, day) {
            return Err(TimestampError::OutOfRange);
        }
        if let Some(weekday) = self.weekday {
            let month8 = u8::try_from(month).map_err(|_| TimestampError::OutOfRange)?;
            let day8 = u8::try_from(day).map_err(|_| TimestampError::OutOfRange)?;
            if chrono_weekday(year, month8, day8) != weekday {
                return Err(TimestampError::InvalidComponent);
            }
        }
        Ok((year, month, day))
    }

    /// Port of `Parsed::to_naive_time`.
    fn to_time(&self) -> Result<(u32, u32, u32, u32), TimestampError> {
        let hour = self.hour.ok_or(TimestampError::InvalidFormat)?;
        let minute = self.minute.ok_or(TimestampError::InvalidFormat)?;
        let (second, mut nano) = match self.second.unwrap_or(0) {
            v @ 0..=59 => (v, 0),
            60 => (59, 1_000_000_000),
            _ => return Err(TimestampError::OutOfRange),
        };
        nano += match self.nanosecond {
            Some(v) if self.second.is_some() => v,
            Some(_) => return Err(TimestampError::InvalidFormat),
            None => 0,
        };
        if !chrono_valid_hms_nano(hour, minute, second, nano) {
            return Err(TimestampError::OutOfRange);
        }
        Ok((hour, minute, second, nano))
    }

    /// Port of `Parsed::to_datetime` (an offset is required).
    fn to_datetime(&self) -> Result<ChronoParsedDateTime, TimestampError> {
        let offset = self.offset.ok_or(TimestampError::InvalidFormat)?;
        let date = self.to_date();
        let time = self.to_time();
        chrono_assemble(date?, time?, offset)
    }

    /// Port of `Parsed::to_naive_datetime_with_offset(0)` (offset ignored).
    fn to_naive_datetime(&self) -> Result<ChronoParsedDateTime, TimestampError> {
        let date = self.to_date();
        let time = self.to_time();
        chrono_assemble(date?, time?, 0)
    }
}

/// The chrono `format::Item`s Ferrum's formats use.
#[derive(Clone, Copy)]
enum ChronoItem<'a> {
    Literal(&'a str),
    Space,
    Year,
    YearMod100,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    ShortMonthName,
    LongMonthName,
    ShortWeekdayName,
    LongWeekdayName,
    /// `%.f`: optional `.` followed by fractional digits.
    Nanosecond,
    /// `%z` / `%:z`.
    TimezoneOffset,
}

/// Port of chrono `format::parse::parse_internal` for [`ChronoItem`]s.
fn chrono_parse_items<'s>(
    fields: &mut ChronoFields,
    mut s: &'s str,
    items: &[ChronoItem<'_>],
) -> Result<&'s str, TimestampError> {
    for item in items {
        match *item {
            ChronoItem::Literal(prefix) => {
                s = s
                    .strip_prefix(prefix)
                    .ok_or(TimestampError::InvalidFormat)?;
            }
            ChronoItem::Space => s = s.trim_start(),
            ChronoItem::Year
            | ChronoItem::YearMod100
            | ChronoItem::Month
            | ChronoItem::Day
            | ChronoItem::Hour
            | ChronoItem::Minute
            | ChronoItem::Second => {
                s = s.trim_start();
                let (rest, value) = if matches!(item, ChronoItem::Year) {
                    if let Some(digits) = s.strip_prefix('-') {
                        let (rest, v) = chrono_scan_number(digits, 1, usize::MAX)?;
                        (rest, 0i64.checked_sub(v).ok_or(TimestampError::OutOfRange)?)
                    } else if let Some(digits) = s.strip_prefix('+') {
                        chrono_scan_number(digits, 1, usize::MAX)?
                    } else {
                        chrono_scan_number(s, 1, 4)?
                    }
                } else {
                    chrono_scan_number(s, 1, 2)?
                };
                s = rest;
                match item {
                    ChronoItem::Year => fields.set_year(value)?,
                    ChronoItem::YearMod100 => fields.set_year_mod_100(value)?,
                    ChronoItem::Month => fields.set_month(value)?,
                    ChronoItem::Day => fields.set_day(value)?,
                    ChronoItem::Hour => fields.set_hour(value)?,
                    ChronoItem::Minute => fields.set_minute(value)?,
                    _ => fields.set_second(value)?,
                }
            }
            ChronoItem::ShortMonthName => {
                let (rest, month0) = chrono_scan_short_month0(s)?;
                s = rest;
                fields.set_month(i64::from(month0) + 1)?;
            }
            ChronoItem::LongMonthName => {
                let (rest, month0) = chrono_scan_short_or_long_month0(s)?;
                s = rest;
                fields.set_month(i64::from(month0) + 1)?;
            }
            ChronoItem::ShortWeekdayName => {
                let (rest, weekday) = chrono_scan_short_weekday(s)?;
                s = rest;
                fields.set_weekday(weekday)?;
            }
            ChronoItem::LongWeekdayName => {
                let (rest, weekday) = chrono_scan_short_or_long_weekday(s)?;
                s = rest;
                fields.set_weekday(weekday)?;
            }
            ChronoItem::Nanosecond => {
                if let Some(digits) = s.strip_prefix('.') {
                    let (rest, nano) = chrono_scan_nanosecond(digits)?;
                    s = rest;
                    fields.set_nanosecond(i64::from(nano))?;
                }
            }
            ChronoItem::TimezoneOffset => {
                let (rest, offset) = chrono_scan_timezone_offset(
                    s.trim_start(),
                    chrono_colon_or_space,
                    false,
                    false,
                    true,
                )?;
                s = rest;
                fields.set_offset(i64::from(offset))?;
            }
        }
    }
    Ok(s)
}

/// Port of chrono `StrftimeItems` for the specifiers Ferrum uses:
/// `%Y %y %m %d %e %H %M %S %a %A %b %h %B %.f %z %:z %%`, optional `-`/`0`/`_`
/// padding flags on numeric specifiers, whitespace runs, and literals.
/// Any other specifier is refused with [`TimestampError::InvalidFormat`].
fn chrono_strftime_items(fmt: &str) -> Result<Vec<ChronoItem<'_>>, TimestampError> {
    let mut items = Vec::new();
    let mut rest = fmt;
    while let Some(c) = rest.chars().next() {
        if c == '%' {
            let mut spec = rest.get(1..).ok_or(TimestampError::InvalidFormat)?;
            let mut next = || -> Result<char, TimestampError> {
                let c = spec.chars().next().ok_or(TimestampError::InvalidFormat)?;
                spec = spec
                    .get(c.len_utf8()..)
                    .ok_or(TimestampError::InvalidFormat)?;
                Ok(c)
            };
            let mut code = next()?;
            let padded = matches!(code, '-' | '0' | '_');
            if padded {
                code = next()?;
            }
            let item = match code {
                'Y' => ChronoItem::Year,
                'y' => ChronoItem::YearMod100,
                'm' => ChronoItem::Month,
                'd' | 'e' => ChronoItem::Day,
                'H' => ChronoItem::Hour,
                'M' => ChronoItem::Minute,
                'S' => ChronoItem::Second,
                'a' if !padded => ChronoItem::ShortWeekdayName,
                'A' if !padded => ChronoItem::LongWeekdayName,
                'b' | 'h' if !padded => ChronoItem::ShortMonthName,
                'B' if !padded => ChronoItem::LongMonthName,
                'z' if !padded => ChronoItem::TimezoneOffset,
                '%' if !padded => ChronoItem::Literal("%"),
                '.' if !padded => match next()? {
                    'f' => ChronoItem::Nanosecond,
                    _ => return Err(TimestampError::InvalidFormat),
                },
                ':' if !padded => match next()? {
                    'z' => ChronoItem::TimezoneOffset,
                    _ => return Err(TimestampError::InvalidFormat),
                },
                _ => return Err(TimestampError::InvalidFormat),
            };
            items.push(item);
            rest = spec;
        } else if c.is_whitespace() {
            let end = rest
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(rest.len());
            items.push(ChronoItem::Space);
            rest = rest.get(end..).ok_or(TimestampError::InvalidFormat)?;
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '%')
                .unwrap_or(rest.len());
            items.push(ChronoItem::Literal(
                rest.get(..end).ok_or(TimestampError::InvalidFormat)?,
            ));
            rest = rest.get(end..).ok_or(TimestampError::InvalidFormat)?;
        }
    }
    Ok(items)
}

/// Parse like chrono 0.4.45 `DateTime::parse_from_rfc3339`: strict
/// `YYYY-MM-DD(T|t| )HH:MM:SS[.f…](Z|z|±HH:MM)` with exactly four year digits,
/// a leap second `:60` accepted at any minute, any number of fractional
/// digits (only the first nine kept), offsets within `±23:59`, and the Unicode
/// minus sign `−` accepted in the offset.
pub fn parse_rfc3339_chrono(s: &str) -> Result<ChronoParsedDateTime, TimestampError> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return Err(TimestampError::InvalidFormat);
    }
    let digit = |i: usize| -> Result<u32, TimestampError> {
        match bytes.get(i) {
            Some(b) if b.is_ascii_digit() => Ok(u32::from(b - b'0')),
            _ => Err(TimestampError::InvalidFormat),
        }
    };
    let expect = |i: usize, allowed: &[u8]| -> Result<(), TimestampError> {
        match bytes.get(i) {
            Some(b) if allowed.contains(b) => Ok(()),
            _ => Err(TimestampError::InvalidFormat),
        }
    };
    let year = digit(0)? * 1000 + digit(1)? * 100 + digit(2)? * 10 + digit(3)?;
    expect(4, b"-")?;
    let month = digit(5)? * 10 + digit(6)?;
    expect(7, b"-")?;
    let day = digit(8)? * 10 + digit(9)?;
    let year = i32::try_from(year).map_err(|_| TimestampError::OutOfRange)?;
    if !chrono_valid_ymd(year, month, day) {
        return Err(TimestampError::OutOfRange);
    }
    expect(10, b"tT ")?;
    let hour = digit(11)? * 10 + digit(12)?;
    expect(13, b":")?;
    let minute = digit(14)? * 10 + digit(15)?;
    expect(16, b":")?;
    let second = digit(17)? * 10 + digit(18)?;
    let (second, extra_nanos) = match second {
        60 => (59, 1_000_000_000),
        _ => (second, 0),
    };
    let (rest, nano) = if bytes.get(19) == Some(&b'.') {
        let (rest, nano) =
            chrono_scan_nanosecond(s.get(20..).ok_or(TimestampError::InvalidFormat)?)?;
        (rest, extra_nanos + nano)
    } else {
        (
            s.get(19..).ok_or(TimestampError::InvalidFormat)?,
            extra_nanos,
        )
    };
    if !chrono_valid_hms_nano(hour, minute, second, nano) {
        return Err(TimestampError::OutOfRange);
    }
    let (rest, offset) =
        chrono_scan_timezone_offset(rest, chrono_colon_required, true, false, true)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    chrono_assemble((year, month, day), (hour, minute, second, nano), offset)
}

/// Parse like chrono 0.4.45 `DateTime<FixedOffset>::from_str`, the relaxed
/// RFC 3339 parser behind chrono's serde `Deserialize` for `DateTime`:
/// unpadded components, whitespace between components, signed years outside
/// `0..=9999`, a `UTC` zone name, and an offset colon that may be missing or
/// replaced by spaces.
pub fn parse_rfc3339_relaxed_chrono(s: &str) -> Result<ChronoParsedDateTime, TimestampError> {
    const DATE_ITEMS: &[ChronoItem<'static>] = &[
        ChronoItem::Year,
        ChronoItem::Space,
        ChronoItem::Literal("-"),
        ChronoItem::Month,
        ChronoItem::Space,
        ChronoItem::Literal("-"),
        ChronoItem::Day,
    ];
    const TIME_ITEMS: &[ChronoItem<'static>] = &[
        ChronoItem::Hour,
        ChronoItem::Space,
        ChronoItem::Literal(":"),
        ChronoItem::Minute,
        ChronoItem::Space,
        ChronoItem::Literal(":"),
        ChronoItem::Second,
        ChronoItem::Nanosecond,
        ChronoItem::Space,
    ];
    let mut fields = ChronoFields::default();
    let rest = chrono_parse_items(&mut fields, s, DATE_ITEMS)?;
    let rest = match rest.as_bytes().first() {
        Some(b't' | b'T' | b' ') => rest.get(1..).ok_or(TimestampError::InvalidFormat)?,
        _ => return Err(TimestampError::InvalidFormat),
    };
    let rest = chrono_parse_items(&mut fields, rest, TIME_ITEMS)?.trim_start();
    let (rest, offset) = if rest
        .as_bytes()
        .get(..3)
        .is_some_and(|head| head.eq_ignore_ascii_case(b"UTC"))
    {
        (rest.get(3..).ok_or(TimestampError::InvalidFormat)?, 0)
    } else {
        chrono_scan_timezone_offset(rest, chrono_colon_or_space, true, false, true)?
    };
    fields.set_offset(i64::from(offset))?;
    if !rest.trim_start().is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    fields.to_datetime()
}

/// Parse like chrono 0.4.45 `DateTime::parse_from_rfc2822`: optional
/// `Day,` prefix that must match the date, 1–2 digit day, 2+ digit year
/// (two-digit years below 50 add 2000, other two- and three-digit years add
/// 1900), optional seconds, numeric `±HHMM` or named zones (`GMT`, `UT`, `Z`,
/// US zones, single military letters as `-0000`), trailing parenthesised
/// comments, and Unicode whitespace between tokens.
pub fn parse_rfc2822_chrono(s: &str) -> Result<ChronoParsedDateTime, TimestampError> {
    let mut fields = ChronoFields::default();
    let mut s = s.trim_start();

    if let Ok((rest, weekday)) = chrono_scan_short_weekday(s) {
        s = rest
            .strip_prefix(',')
            .ok_or(TimestampError::InvalidFormat)?;
        fields.set_weekday(weekday)?;
    }

    s = s.trim_start();
    let (rest, day) = chrono_scan_number(s, 1, 2)?;
    fields.set_day(day)?;
    s = chrono_scan_space(rest)?;
    let (rest, month0) = chrono_scan_short_month0(s)?;
    fields.set_month(1 + i64::from(month0))?;
    s = chrono_scan_space(rest)?;

    let before = s.len();
    let (rest, mut year) = chrono_scan_number(s, 2, usize::MAX)?;
    let year_len = before - rest.len();
    s = rest;
    match (year_len, year) {
        (2, 0..=49) => year += 2000,
        (2, 50..=99) | (3, _) => year += 1900,
        _ => {}
    }
    fields.set_year(year)?;

    s = chrono_scan_space(s)?;
    let (rest, hour) = chrono_scan_number(s, 2, 2)?;
    fields.set_hour(hour)?;
    s = rest
        .trim_start()
        .strip_prefix(':')
        .ok_or(TimestampError::InvalidFormat)?
        .trim_start();
    let (rest, minute) = chrono_scan_number(s, 2, 2)?;
    fields.set_minute(minute)?;
    s = rest;
    if let Some(after_colon) = s.trim_start().strip_prefix(':') {
        let (rest, second) = chrono_scan_number(after_colon, 2, 2)?;
        fields.set_second(second)?;
        s = rest;
    }

    s = chrono_scan_space(s)?;
    let (rest, offset) = chrono_scan_timezone_offset_2822(s)?;
    fields.set_offset(i64::from(offset))?;
    s = rest;

    while let Ok(rest) = chrono_scan_comment_2822(s) {
        s = rest;
    }
    if !s.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    fields.to_datetime()
}

/// Parse like chrono 0.4.45 `DateTime::parse_from_str(s, fmt)`: the format
/// must yield a date, a time and an offset. Supported specifiers:
/// `%Y %y %m %d %e %H %M %S %a %A %b %h %B %.f %z %:z %%` (plus `-`/`0`/`_`
/// padding flags on numeric ones); any other specifier is refused with
/// [`TimestampError::InvalidFormat`] rather than parsed differently.
pub fn parse_from_str_chrono(s: &str, fmt: &str) -> Result<ChronoParsedDateTime, TimestampError> {
    let items = chrono_strftime_items(fmt)?;
    let mut fields = ChronoFields::default();
    let rest = chrono_parse_items(&mut fields, s, &items)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    fields.to_datetime()
}

/// Parse like chrono 0.4.45 `NaiveDateTime::parse_from_str(s, fmt)`: any
/// parsed offset is validated but ignored, and the result carries offset `0`
/// (so [`ChronoParsedDateTime::unix_timestamp`] equals chrono's
/// `naive.and_utc().timestamp()`).
pub fn parse_naive_from_str_chrono(
    s: &str,
    fmt: &str,
) -> Result<ChronoParsedDateTime, TimestampError> {
    let items = chrono_strftime_items(fmt)?;
    let mut fields = ChronoFields::default();
    let rest = chrono_parse_items(&mut fields, s, &items)?;
    if !rest.is_empty() {
        return Err(TimestampError::InvalidFormat);
    }
    fields.to_naive_datetime()
}
