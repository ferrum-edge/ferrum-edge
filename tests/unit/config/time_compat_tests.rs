//! Byte-for-byte compatibility tests for `ferrum_edge::time_compat` against
//! chrono 0.4.45's `DateTime<Utc>` across serde, SQLite, MySQL, PostgreSQL,
//! and `sqlx::Any` (issue #7419, Phase 1). chrono is no longer a dependency:
//! its outputs for every case below were recorded once from chrono itself in
//! `tests/fixtures/time_compat/chrono_0_4_45_value_oracle.jsonl` and are
//! compared here as fixed expected values.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration as StdDuration, UNIX_EPOCH};

use ferrum_edge::time_compat::{
    SecondsFormat, TimestampError, UtcTimestamp, decode_sqlite_julian_day,
    parse_mysql_datetime_text, parse_postgres_datetime_text, parse_rfc3339,
    parse_sqlite_datetime_text,
};
use serde_json::Value;
use sqlx::any::AnyPoolOptions;
use sqlx::encode::IsNull;
use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType};
use sqlx::{Encode, MySql, Postgres, Row, Sqlite, SqlitePool, Type};
use time::{Date, Month, OffsetDateTime, SignedDuration, Time, UtcOffset};

const ORACLE_JSONL: &str =
    include_str!("../../fixtures/time_compat/chrono_0_4_45_value_oracle.jsonl");

/// chrono's outputs for one `DateTime::<Utc>::from_timestamp(secs, nanos)`.
#[derive(Debug, serde::Deserialize)]
struct InstantRecord {
    secs: i64,
    nanos: u32,
    /// `to_rfc3339()`.
    rfc3339: String,
    /// `to_rfc3339_opts(mode, use_z)` for Secs, Millis, Micros, Nanos, AutoSi,
    /// each with `use_z` false then true.
    opts: Vec<String>,
    /// `Display`.
    display: String,
    debug: String,
    json: String,
    yaml: String,
    /// `timestamp()`, `timestamp_subsec_nanos()`, `timestamp_millis()`.
    ts: i64,
    subsec: u32,
    millis: i64,
    /// `format("%Y-%m-%dT%H:%M:%SZ")`, `format("%Y%m%d")`,
    /// `format("%Y%m%d%H%M%S")`.
    secs_z: String,
    ymd: String,
    ymdhms: String,
    rfc2822: String,
    /// `format("%d/%b/%Y:%H:%M:%S %z")`.
    clf: String,
    /// MySQL binary `Encode` bytes (hex) and `size_hint`.
    mysql: String,
    mysql_hint: usize,
    /// PostgreSQL binary `Encode` bytes (hex) and `size_hint`.
    pg: String,
    pg_hint: usize,
    /// Bytes SQLite stored for a bound value in a DATETIME and a TEXT column
    /// (hex of `CAST(.. AS BLOB)`).
    sqlite_dt: String,
    sqlite_txt: String,
}

impl InstantRecord {
    fn opts(&self, mode: SecondsFormat, use_z: bool) -> &str {
        let index = match mode {
            SecondsFormat::Secs => 0,
            SecondsFormat::Millis => 1,
            SecondsFormat::Micros => 2,
            SecondsFormat::Nanos => 3,
            SecondsFormat::AutoSi => 4,
        };
        &self.opts[index * 2 + usize::from(use_z)]
    }
}

fn unhex(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text).unwrap_or_else(|error| panic!("bad oracle hex {hex_text:?}: {error}"))
}

struct Oracle {
    instants: HashMap<(i64, u32), InstantRecord>,
    lines: Vec<Value>,
}

impl Oracle {
    fn instant(&self, secs: i64, nanos: u32) -> &InstantRecord {
        self.instants
            .get(&(secs, nanos))
            .unwrap_or_else(|| panic!("no chrono oracle record for ({secs}, {nanos})"))
    }

    fn all(&self, kind: &str) -> impl Iterator<Item = &Value> {
        let kind = kind.to_string();
        self.lines
            .iter()
            .filter(move |line| line["k"] == kind.as_str())
    }

    /// The single line of `kind` whose `field` equals `key`.
    fn find(&self, kind: &str, field: &str, key: impl Into<Value>) -> &Value {
        let key = key.into();
        let mut found = self.all(kind).filter(|line| line[field] == key);
        let line = found
            .next()
            .unwrap_or_else(|| panic!("no chrono oracle {kind} line with {field} = {key}"));
        assert!(found.next().is_none(), "duplicate oracle {kind} line {key}");
        line
    }

    fn misc(&self) -> &Value {
        self.all("misc").next().expect("oracle misc line")
    }
}

fn oracle() -> &'static Oracle {
    static ORACLE: OnceLock<Oracle> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let mut instants = HashMap::new();
        let mut lines = Vec::new();
        for line in ORACLE_JSONL.lines().filter(|line| !line.trim().is_empty()) {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("bad oracle line {line:?}: {error}"));
            if value["k"] == "inst" {
                let record: InstantRecord = serde_json::from_value(value)
                    .unwrap_or_else(|error| panic!("bad oracle instant {line:?}: {error}"));
                assert_eq!(record.opts.len(), 10, "{line:?}");
                assert!(
                    instants
                        .insert((record.secs, record.nanos), record)
                        .is_none(),
                    "duplicate oracle instant {line:?}"
                );
            } else {
                lines.push(value);
            }
        }
        Oracle { instants, lines }
    })
}

fn int(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("oracle value {value} is not an integer"))
}

fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("oracle value {value} is not a string"))
}

/// chrono's `(timestamp(), timestamp_subsec_nanos())` on an oracle line.
fn instant_of(line: &Value) -> (i64, u32) {
    (
        int(&line["ts"]),
        u32::try_from(int(&line["subsec"])).expect("subsec nanos"),
    )
}

/// Representative instants covering whole seconds, ms/us/ns AutoSi buckets,
/// trailing-zero subseconds, sub-microsecond nanos, midnight, leap day,
/// Unix epoch, pre-epoch, Postgres epoch (2000-01-01), pre-2000, and year
/// boundaries.
fn representative_instants() -> Vec<(i64, u32)> {
    vec![
        // Unix epoch (midnight, zero subsec)
        (0, 0),
        // Pre-epoch with subseconds (1969-12-31T23:59:59.500Z)
        (-1, 500_000_000),
        // Pre-epoch with nanoseconds (1969-12-31T23:59:58.123456789Z)
        (-2, 123_456_789),
        // Postgres epoch exact (2000-01-01T00:00:00Z, midnight -> MySQL len 4)
        (946_684_800, 0),
        // Just before Postgres epoch with microsecond (1999-12-31T23:59:59.999999Z)
        (946_684_799, 999_999_000),
        // Just before Postgres epoch with sub-microsecond nanos (truncation check)
        (946_684_799, 999_999_500),
        // Leap day whole second (2024-02-29T00:00:00Z, midnight -> MySQL len 4)
        (1_709_164_800, 0),
        // Non-midnight whole second (2026-01-02T03:04:05Z -> MySQL len 7)
        (1_767_323_045, 0),
        // Millisecond-aligned AutoSi (3 fractional digits: .100, .005, .123)
        (1_767_323_045, 100_000_000),
        (1_767_323_045, 5_000_000),
        (1_767_323_045, 123_000_000),
        // Microsecond-aligned AutoSi (6 fractional digits: .123400, .000001)
        (1_767_323_045, 123_400_000),
        (1_767_323_045, 1_000),
        // Nanosecond-precision AutoSi (9 fractional digits: .000000500, .123456789)
        (1_767_323_045, 500),
        (1_767_323_045, 123_456_789),
        // Early year within MySQL supported range (1000-01-01T00:00:00Z)
        (-30_610_224_000, 0),
        // Far future within 4-digit RFC 3339 / MySQL range (9999-12-31T23:59:59.999999Z)
        (253_402_300_799, 999_999_000),
    ]
}

fn pair_for(secs: i64, nanos: u32) -> (UtcTimestamp, &'static InstantRecord) {
    let ts = UtcTimestamp::from_unix_timestamp_nanos(secs, nanos)
        .expect("representative instant valid for UtcTimestamp");
    let ch = oracle().instant(secs, nanos);
    assert_eq!(ts.unix_timestamp(), ch.ts);
    assert_eq!(ts.subsec_nanos(), ch.subsec);
    (ts, ch)
}

#[test]
fn rfc3339_formatting_matches_chrono_byte_for_byte() {
    let modes = [
        SecondsFormat::Secs,
        SecondsFormat::Millis,
        SecondsFormat::Micros,
        SecondsFormat::Nanos,
        SecondsFormat::AutoSi,
    ];

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        assert_eq!(
            ts.to_rfc3339(),
            ch.rfc3339,
            "to_rfc3339 mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_rfc3339_z(),
            ch.opts(SecondsFormat::AutoSi, true),
            "to_rfc3339_z mismatch for ({secs}, {nanos})"
        );

        for mode in modes {
            for use_z in [false, true] {
                assert_eq!(
                    ts.to_rfc3339_opts(mode, use_z),
                    ch.opts(mode, use_z),
                    "to_rfc3339_opts({mode:?}, {use_z}) mismatch for ({secs}, {nanos})"
                );
            }
        }
    }

    // Year 0001 boundary (valid for RFC 3339 / SQLite / Postgres, outside MySQL 1000..=9999).
    let misc = oracle().misc();
    let year1_date = Date::from_calendar_date(1, Month::January, 1).unwrap();
    let year1_ts = UtcTimestamp::from_utc_date_time(year1_date, Time::MIDNIGHT);
    assert_eq!(year1_ts.unix_timestamp(), int(&misc["year1_ts"]));
    assert_eq!(year1_ts.to_rfc3339(), text(&misc["year1_rfc3339"]));
    assert_eq!(year1_ts.to_rfc3339_z(), "0001-01-01T00:00:00Z");
}

#[test]
fn chrono_display_and_default_match_chrono_byte_for_byte() {
    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);
        assert_eq!(
            ts.to_chrono_display(),
            ch.display,
            "to_chrono_display mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            format!("{ts:?}"),
            ch.debug,
            "Debug mismatch for ({secs}, {nanos})"
        );
    }
    for year in [-9999, -1, 0, 1, 9999] {
        let date = Date::from_calendar_date(year, Month::December, 31).unwrap();
        let ts = UtcTimestamp::from_utc_date_time(date, Time::MIDNIGHT);
        let ch = oracle().find("year_display", "year", year);
        assert_eq!(ts.unix_timestamp(), int(&ch["ts"]), "year {year}");
        assert_eq!(ts.to_chrono_display(), text(&ch["display"]), "year {year}");
    }

    assert_eq!(UtcTimestamp::default(), UtcTimestamp::UNIX_EPOCH);
    assert_eq!(
        UtcTimestamp::default().to_rfc3339(),
        text(&oracle().misc()["default_rfc3339"])
    );
}

#[test]
fn serde_json_and_yaml_match_chrono_byte_for_byte() {
    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        // Byte-identical output also means chrono reads what UtcTimestamp writes.
        let ts_json = serde_json::to_string(&ts).expect("serialize UtcTimestamp to JSON");
        assert_eq!(
            ts_json, ch.json,
            "JSON serialization mismatch for ({secs}, {nanos})"
        );

        // Deserialize JSON written by chrono into UtcTimestamp.
        let decoded_ts: UtcTimestamp =
            serde_json::from_str(&ch.json).expect("deserialize chrono JSON into UtcTimestamp");
        assert_eq!(decoded_ts, ts);

        let ts_yaml = serde_yaml::to_string(&ts).expect("serialize UtcTimestamp to YAML");
        assert_eq!(
            ts_yaml, ch.yaml,
            "YAML serialization mismatch for ({secs}, {nanos})"
        );
        let decoded_yaml: UtcTimestamp =
            serde_yaml::from_str(&ch.yaml).expect("deserialize chrono YAML into UtcTimestamp");
        assert_eq!(decoded_yaml, ts);
    }

    // Non-UTC offsets normalize to the exact same UTC instant as chrono.
    for input in [
        "\"2026-01-02T05:04:05+02:00\"",
        "\"2026-01-01T21:34:05.123-05:30\"",
        "\"2026-01-02t03:04:05.123456789z\"",
        "\"2026-01-02 03:04:05-00:00\"",
        "\"2026-01-02T03:04:05.12345678999Z\"",
    ] {
        let ts: UtcTimestamp = serde_json::from_str(input).expect("UtcTimestamp parses input");
        let ch = instant_of(oracle().find("serde_in", "i", input));
        assert_eq!(
            (ts.unix_timestamp(), ts.subsec_nanos()),
            ch,
            "input={input}"
        );
    }
}

#[test]
fn parse_rejects_malformed_and_overflow_inputs_without_panicking() {
    for bad in [
        "",
        "not-a-timestamp",
        "2026-01-02",
        "2026-01-02T03:04:05",
        "2026-01-02T03:04:05.Z",
        "2026-01-02T03:04:05Ztrailing",
        "2026-13-01T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-01-02T24:00:00Z",
        "2026-01-02T00:60:00Z",
        "2026-01-02T00:00:60Z",
        "2026-01-02T00:00:00+24:00",
        "2026-01-02T00:00:00-00:60",
        // Overflowing supported year range (`-9999..=9999`) directly or during
        // offset-to-UTC conversion:
        "9999-12-31T23:30:00-05:00",
        "-9999-01-01T00:30:00+05:00",
        "+10000-01-01T00:00:00Z",
        "-10000-01-01T00:00:00Z",
    ] {
        assert!(
            parse_rfc3339(bad).is_err(),
            "parse_rfc3339 unexpectedly accepted {bad:?}"
        );
    }

    let max_year_end = UtcTimestamp::parse_from_rfc3339("9999-12-31T23:59:59Z").unwrap();
    assert!(
        max_year_end
            .checked_add(SignedDuration::seconds(1))
            .is_none()
    );
    let min_year_start = UtcTimestamp::parse_from_rfc3339("-9999-01-01T00:00:00Z").unwrap();
    assert!(
        min_year_start
            .checked_sub(SignedDuration::seconds(1))
            .is_none()
    );

    assert_eq!(
        UtcTimestamp::from_unix_timestamp_nanos(0, 1_000_000_000),
        Err(TimestampError::InvalidComponent)
    );
    assert!(decode_sqlite_julian_day(f64::NAN).is_err());
    assert!(decode_sqlite_julian_day(f64::INFINITY).is_err());
    assert!(UtcTimestamp::decode_mysql_binary(&[]).is_err());
    assert!(UtcTimestamp::decode_mysql_binary(&[0]).is_err());
    assert!(UtcTimestamp::decode_mysql_binary(&[4, 0xea, 0x07]).is_err());
    assert!(UtcTimestamp::decode_mysql_binary(&[5, 0xea, 0x07, 1, 2, 3]).is_err());
    assert_eq!(
        UtcTimestamp::decode_mysql_binary(&[4, 0x10, 0x27, 1, 1]),
        Err(TimestampError::OutOfRange)
    );
    assert!(UtcTimestamp::decode_postgres_binary(&[0u8; 7]).is_err());
}

/// Phase 2 call sites replaced `Utc::now().timestamp()`,
/// `.timestamp_millis()` and `.format("%Y-%m-%dT%H:%M:%SZ")` with
/// `unix_timestamp()`, `unix_timestamp_millis()` and
/// `to_rfc3339_opts(SecondsFormat::Secs, true)`. Pin all three to chrono,
/// including pre-epoch instants where millisecond flooring matters.
#[test]
fn unix_epoch_accessors_and_secs_z_format_match_chrono() {
    let mut instants = representative_instants();
    instants.extend([
        // Pre-epoch sub-millisecond remainders: chrono floors toward
        // negative infinity, never toward zero.
        (-1, 999_500_000),
        (-1, 999_999_999),
        (-1, 1),
        (-1, 0),
        (0, 999_999),
        (0, 1_000_000),
    ]);

    for (secs, nanos) in instants {
        let (ts, ch) = pair_for(secs, nanos);
        assert_eq!(
            ts.unix_timestamp(),
            ch.ts,
            "unix_timestamp mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.unix_timestamp_millis(),
            ch.millis,
            "unix_timestamp_millis mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_rfc3339_opts(SecondsFormat::Secs, true),
            ch.secs_z,
            "Secs+Z vs strftime mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_compact_date(),
            ch.ymd,
            "compact date mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_compact_date_time(),
            ch.ymdhms,
            "compact date-time mismatch for ({secs}, {nanos})"
        );
    }

    // Years outside 0..=9999 get chrono's explicit sign. `UtcTimestamp::now()`
    // reads the wall clock directly, and `time/large-dates` is unified in by
    // bson, so a far-future clock reaches these formatters.
    for year in [-1, 10_000] {
        let ch = oracle().find("compact_year", "year", year);
        let Ok(date) = Date::from_calendar_date(year, Month::December, 31) else {
            // Without `time/large-dates` the year is unrepresentable (it was
            // when the oracle was recorded, if the record says so).
            assert_eq!(ch["skipped"].as_bool(), Some(true), "year {year}");
            continue;
        };
        let ts = UtcTimestamp::from_utc_date_time(date, Time::from_hms(10, 20, 30).unwrap());
        assert_eq!(ts.unix_timestamp(), int(&ch["ts"]), "year {year}");
        assert_eq!(ts.to_compact_date(), text(&ch["ymd"]), "year {year}");
        assert_eq!(
            ts.to_compact_date_time(),
            text(&ch["ymdhms"]),
            "year {year}"
        );
    }

    // The wall clock: millis floor the nanosecond instant, and the RFC 3339
    // text parses back to the same instant.
    let ts = UtcTimestamp::now();
    assert_eq!(
        i128::from(ts.unix_timestamp_millis()),
        ts.unix_timestamp_nanos().div_euclid(1_000_000)
    );
    assert_eq!(parse_rfc3339(&ts.to_rfc3339()), Ok(ts));
}

#[test]
fn system_time_and_duration_arithmetic_work_across_epoch() {
    let post = UNIX_EPOCH + StdDuration::new(1_767_323_045, 123_456_789);
    let ts_post = UtcTimestamp::from_system_time(post).expect("post-epoch SystemTime");
    assert_eq!(ts_post.to_rfc3339_z(), "2026-01-02T03:04:05.123456789Z");

    let pre_half = UNIX_EPOCH - StdDuration::from_millis(500);
    let ts_pre_half = UtcTimestamp::from_system_time(pre_half).expect("pre-epoch 500ms");
    assert_eq!(ts_pre_half.to_rfc3339_z(), "1969-12-31T23:59:59.500Z");

    let pre_exact = UNIX_EPOCH - StdDuration::from_secs(1);
    let ts_pre_exact = UtcTimestamp::from_system_time(pre_exact).expect("pre-epoch 1s");
    assert_eq!(ts_pre_exact.to_rfc3339_z(), "1969-12-31T23:59:59Z");

    let shifted = ts_post
        .checked_add(SignedDuration::seconds(60))
        .expect("add 60s");
    assert_eq!(shifted - ts_post, SignedDuration::seconds(60));
    assert_eq!(
        shifted.checked_sub(SignedDuration::seconds(60)),
        Some(ts_post)
    );

    // Non-UTC OffsetDateTime normalizes to UTC.
    let offset = UtcOffset::from_hms(2, 0, 0).unwrap();
    let local_dt = ts_post.into_offset_date_time().to_offset(offset);
    let normalized = UtcTimestamp::try_from_offset_date_time(local_dt).unwrap();
    assert_eq!(normalized, ts_post);
}

/// Asserts the recorded chrono `type_info()` equals `time::OffsetDateTime`'s
/// for `field` (so `OffsetDateTime` stands in for chrono below) and returns
/// chrono's recorded `Debug` text.
fn chrono_type_info_debug(field: &str) -> &'static str {
    let info = oracle()
        .all("type_info")
        .next()
        .expect("oracle type_info line");
    assert_eq!(
        info[format!("{field}_eq").as_str()].as_bool(),
        Some(true),
        "chrono and OffsetDateTime {field} type_info differed when recorded"
    );
    assert_eq!(
        info[format!("{field}_chrono").as_str()],
        info[format!("{field}_time").as_str()],
        "{field}"
    );
    text(&info[format!("{field}_chrono").as_str()])
}

#[tokio::test]
async fn sqlite_roundtrip_is_byte_identical_to_chrono_and_reads_legacy_rows() {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");

    sqlx::query(
        "CREATE TABLE ts_parity (
            id INTEGER PRIMARY KEY,
            dt_compat DATETIME NOT NULL,
            dt_chrono DATETIME NOT NULL,
            txt_compat TEXT NOT NULL,
            txt_chrono TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("create ts_parity table");

    assert_eq!(
        format!("{:?}", <UtcTimestamp as Type<Sqlite>>::type_info()),
        chrono_type_info_debug("sqlite")
    );
    assert_eq!(
        <UtcTimestamp as Type<Sqlite>>::type_info(),
        <OffsetDateTime as Type<Sqlite>>::type_info()
    );

    for (idx, (secs, nanos)) in representative_instants().into_iter().enumerate() {
        let (ts, ch) = pair_for(secs, nanos);
        // sqlx-sqlite binds chrono's DateTime<Utc> as TEXT, so the recorded
        // stored bytes are exactly what chrono wrote.
        let chrono_dt = String::from_utf8(unhex(&ch.sqlite_dt)).expect("chrono DATETIME text");
        let chrono_txt = String::from_utf8(unhex(&ch.sqlite_txt)).expect("chrono TEXT text");

        sqlx::query(
            "INSERT INTO ts_parity (id, dt_compat, dt_chrono, txt_compat, txt_chrono)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(idx as i64)
        .bind(ts)
        .bind(chrono_dt.as_str())
        .bind(ts)
        .bind(chrono_txt.as_str())
        .execute(&pool)
        .await
        .expect("insert parity row");

        // Compare raw stored bytes directly in SQLite.
        let row = sqlx::query(
            "SELECT
                CAST(dt_compat AS BLOB),
                CAST(dt_chrono AS BLOB),
                CAST(txt_compat AS BLOB),
                CAST(txt_chrono AS BLOB),
                dt_compat,
                dt_chrono,
                txt_chrono
             FROM ts_parity WHERE id = ?1",
        )
        .bind(idx as i64)
        .fetch_one(&pool)
        .await
        .expect("select parity row");

        let dt_compat_bytes: Vec<u8> = row.try_get(0).expect("dt_compat blob");
        let dt_chrono_bytes: Vec<u8> = row.try_get(1).expect("dt_chrono blob");
        let txt_compat_bytes: Vec<u8> = row.try_get(2).expect("txt_compat blob");
        let txt_chrono_bytes: Vec<u8> = row.try_get(3).expect("txt_chrono blob");

        assert_eq!(dt_chrono_bytes, unhex(&ch.sqlite_dt));
        assert_eq!(txt_chrono_bytes, unhex(&ch.sqlite_txt));
        assert_eq!(
            dt_compat_bytes, dt_chrono_bytes,
            "SQLite DATETIME bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            txt_compat_bytes, txt_chrono_bytes,
            "SQLite TEXT bytes diverged from chrono for ({secs}, {nanos})"
        );

        // UtcTimestamp reads its own and chrono-written columns. Since the
        // bytes are identical, chrono reads UtcTimestamp-written columns too.
        let compat_from_compat: UtcTimestamp = row.try_get(4).expect("decode compat from compat");
        let compat_from_chrono: UtcTimestamp = row.try_get(5).expect("decode compat from chrono");
        let compat_from_txt: UtcTimestamp = row.try_get(6).expect("decode compat from chrono text");

        assert_eq!(compat_from_compat, ts);
        assert_eq!(compat_from_chrono, ts);
        assert_eq!(compat_from_txt, ts);
    }

    // Legacy SQLite row formats: TEXT (CURRENT_TIMESTAMP, space separator,
    // minute precision, Z, explicit offsets), INTEGER Unix seconds, and REAL
    // Julian day (both post-epoch and pre-epoch).
    let legacy_text_cases = [
        ("2026-01-02 03:04:05", "2026-01-02T03:04:05Z"),
        ("2026-01-02 03:04:05.123", "2026-01-02T03:04:05.123Z"),
        ("2026-01-02 03:04:05.123456", "2026-01-02T03:04:05.123456Z"),
        (
            "2026-01-02 03:04:05.123456789",
            "2026-01-02T03:04:05.123456789Z",
        ),
        ("2026-01-02 03:04:05Z", "2026-01-02T03:04:05Z"),
        ("2026-01-02 05:04:05+02:00", "2026-01-02T03:04:05Z"),
        ("2026-01-01 21:34:05.5-05:30", "2026-01-02T03:04:05.500Z"),
        ("2026-01-02 03:04", "2026-01-02T03:04:00Z"),
        ("2026-01-02 03:04Z", "2026-01-02T03:04:00Z"),
        ("2026-01-02 05:04+02:00", "2026-01-02T03:04:00Z"),
        ("2026-01-02T03:04", "2026-01-02T03:04:00Z"),
        ("2026-01-02T03:04Z", "2026-01-02T03:04:00Z"),
        ("2026-01-02T05:04+02:00", "2026-01-02T03:04:00Z"),
        ("2026-01-02T03:04:05", "2026-01-02T03:04:05Z"),
        ("2026-01-02T03:04:05.25", "2026-01-02T03:04:05.250Z"),
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"),
        ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05Z"),
    ];

    for (raw, expected_rfc3339_z) in legacy_text_cases {
        let row = sqlx::query("SELECT ?1")
            .bind(raw)
            .fetch_one(&pool)
            .await
            .expect("select legacy text");
        let compat_val: UtcTimestamp = row
            .try_get(0)
            .unwrap_or_else(|e| panic!("UtcTimestamp failed on legacy SQLite text {raw:?}: {e}"));
        let chrono_val = oracle().find("sqlite_text", "i", raw);
        assert_eq!(
            chrono_val["ok"].as_bool(),
            Some(true),
            "chrono decoded {raw:?}"
        );
        assert_eq!(compat_val.to_rfc3339_z(), expected_rfc3339_z, "raw={raw:?}");
        assert_eq!(
            (compat_val.unix_timestamp(), compat_val.subsec_nanos()),
            instant_of(chrono_val),
            "raw={raw:?}"
        );
        assert_eq!(parse_sqlite_datetime_text(raw).unwrap(), compat_val);
    }

    // Legacy INTEGER Unix seconds (positive, epoch, negative pre-epoch).
    for unix_secs in [1_767_323_045_i64, 0, -86_400] {
        let row = sqlx::query("SELECT ?1")
            .bind(unix_secs)
            .fetch_one(&pool)
            .await
            .expect("select legacy integer");
        let compat_val: UtcTimestamp = row.try_get(0).expect("decode integer timestamp");
        let chrono_val = instant_of(oracle().find("sqlite_int", "i", unix_secs));
        assert_eq!(compat_val.unix_timestamp(), chrono_val.0);
        assert_eq!(compat_val.subsec_nanos(), 0);
        assert_eq!(chrono_val.1, 0);
    }

    // Legacy REAL Julian day numbers (pre-epoch and post-epoch).
    for (unix_secs, subsec_nanos) in [(-1_i64, 500_000_000_u32), (1, 500_000_000)] {
        let julian = 2_440_587.5 + (unix_secs as f64 + f64::from(subsec_nanos) / 1e9) / 86_400.0;
        let chrono_val = oracle().find("sqlite_julian", "secs", unix_secs);
        assert_eq!(
            text(&chrono_val["julian_bits"]),
            format!("{:016x}", julian.to_bits()),
            "the recorded Julian day input"
        );
        let (chrono_secs, chrono_nanos) = instant_of(chrono_val);
        let row = sqlx::query("SELECT ?1")
            .bind(julian)
            .fetch_one(&pool)
            .await
            .expect("select legacy julian real");
        let compat_val: UtcTimestamp = row.try_get(0).expect("decode julian day");
        let expected = UtcTimestamp::from_unix_timestamp_nanos(unix_secs, subsec_nanos).unwrap();
        let diff_us = (compat_val - expected).whole_microseconds().abs();
        assert!(diff_us < 1_000, "julian diff too large: {diff_us} us");
        assert_eq!(compat_val.unix_timestamp(), chrono_secs);
        assert!(
            (i64::from(compat_val.subsec_nanos()) - i64::from(chrono_nanos)).abs() <= 1,
            "julian subsec diverged from chrono"
        );
    }

    // Invalid SQLite text fails closed, as it did for chrono.
    assert_eq!(
        oracle().find("sqlite_text", "i", "not-a-date")["ok"].as_bool(),
        Some(false)
    );
    assert_eq!(
        oracle().all("sqlite_bad_literal").next().unwrap()["ok"].as_bool(),
        Some(false)
    );
    let bad_row = sqlx::query("SELECT 'not-a-date'")
        .fetch_one(&pool)
        .await
        .expect("select invalid text");
    assert!(bad_row.try_get::<UtcTimestamp, _>(0).is_err());
}

#[test]
fn mysql_binary_wire_encoding_matches_chrono_byte_for_byte_and_decodes_legacy_formats() {
    assert_eq!(
        format!("{:?}", <UtcTimestamp as Type<MySql>>::type_info()),
        chrono_type_info_debug("mysql")
    );
    assert_eq!(
        <UtcTimestamp as Type<MySql>>::type_info(),
        <OffsetDateTime as Type<MySql>>::type_info()
    );
    assert!(<UtcTimestamp as Type<MySql>>::compatible(
        &<OffsetDateTime as Type<MySql>>::type_info()
    ));
    assert!(<UtcTimestamp as Type<MySql>>::compatible(
        &<String as Type<MySql>>::type_info()
    ));

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);
        let chrono_buf = unhex(&ch.mysql);

        let mut compat_buf = Vec::new();
        let compat_null = <UtcTimestamp as Encode<'_, MySql>>::encode_by_ref(&ts, &mut compat_buf)
            .expect("encode UtcTimestamp for MySQL");
        assert!(
            matches!(compat_null, IsNull::No),
            "UtcTimestamp MySQL encode returned IsNull::Yes for ({secs}, {nanos})"
        );

        assert_eq!(
            compat_buf, chrono_buf,
            "MySQL binary wire bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            <UtcTimestamp as Encode<'_, MySql>>::size_hint(&ts),
            ch.mysql_hint,
            "MySQL size_hint mismatch for ({secs}, {nanos})"
        );

        // Decode the chrono-produced binary buffer back through UtcTimestamp.
        let decoded = UtcTimestamp::decode_mysql_binary(&chrono_buf)
            .expect("decode chrono MySQL binary packet");
        let expected_micro_truncated =
            UtcTimestamp::from_unix_timestamp_nanos(secs, (nanos / 1_000) * 1_000).unwrap();
        assert_eq!(
            decoded, expected_micro_truncated,
            "MySQL binary decode mismatch for ({secs}, {nanos})"
        );
    }

    // Verify exact packet lengths: 4-byte midnight, 7-byte whole-second, 11-byte subsec.
    let midnight = UtcTimestamp::parse_from_rfc3339("2026-01-02T00:00:00Z").unwrap();
    let mut buf = Vec::new();
    midnight.encode_mysql_binary(&mut buf).unwrap();
    assert_eq!(buf.len(), 5);
    assert_eq!(buf[0], 4);

    let whole_sec = UtcTimestamp::parse_from_rfc3339("2026-01-02T03:04:05Z").unwrap();
    buf.clear();
    whole_sec.encode_mysql_binary(&mut buf).unwrap();
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[0], 7);

    let with_micros = UtcTimestamp::parse_from_rfc3339("2026-01-02T03:04:05.123456Z").unwrap();
    buf.clear();
    with_micros.encode_mysql_binary(&mut buf).unwrap();
    assert_eq!(buf.len(), 12);
    assert_eq!(buf[0], 11);

    // MySQL text protocol and Ferrum's legacy VARCHAR(64) timestamp rows.
    for (raw, expected) in [
        ("2026-01-02 03:04:05", "2026-01-02T03:04:05Z"),
        ("2026-01-02 03:04:05.5", "2026-01-02T03:04:05.500Z"),
        ("2026-01-02 03:04:05.123456", "2026-01-02T03:04:05.123456Z"),
        ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05Z"),
        (
            "2026-01-02T03:04:05.123456789+00:00",
            "2026-01-02T03:04:05.123456789Z",
        ),
        ("2026-01-02T03:04:05.123Z", "2026-01-02T03:04:05.123Z"),
    ] {
        let parsed = parse_mysql_datetime_text(raw)
            .unwrap_or_else(|e| panic!("parse_mysql_datetime_text failed on {raw:?}: {e}"));
        assert_eq!(parsed.to_rfc3339_z(), expected, "raw={raw:?}");

        // Cross-check space-separated rows against chrono's MySQL text parser
        // (`NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f")`).
        if !raw.contains('T') {
            let ch = instant_of(oracle().find("mysql_text", "i", raw));
            assert_eq!(
                (parsed.unix_timestamp(), parsed.subsec_nanos()),
                ch,
                "raw={raw:?}"
            );
        }
    }
}

#[test]
fn postgres_binary_and_text_wire_formats_match_chrono_byte_for_byte() {
    assert_eq!(
        format!("{:?}", <UtcTimestamp as Type<Postgres>>::type_info()),
        chrono_type_info_debug("pg")
    );
    assert_eq!(
        format!("{:?}", <UtcTimestamp as PgHasArrayType>::array_type_info()),
        chrono_type_info_debug("pg_arr")
    );
    assert_eq!(
        <UtcTimestamp as Type<Postgres>>::type_info(),
        <OffsetDateTime as Type<Postgres>>::type_info()
    );
    assert_eq!(
        <UtcTimestamp as PgHasArrayType>::array_type_info(),
        <OffsetDateTime as PgHasArrayType>::array_type_info()
    );
    assert!(<UtcTimestamp as Type<Postgres>>::compatible(
        &<OffsetDateTime as Type<Postgres>>::type_info()
    ));
    assert!(<UtcTimestamp as Type<Postgres>>::compatible(
        &<String as Type<Postgres>>::type_info()
    ));

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);
        let chrono_buf = unhex(&ch.pg);

        let mut compat_buf = PgArgumentBuffer::default();
        let compat_null =
            <UtcTimestamp as Encode<'_, Postgres>>::encode_by_ref(&ts, &mut compat_buf)
                .expect("encode UtcTimestamp for Postgres");
        assert!(
            matches!(compat_null, IsNull::No),
            "UtcTimestamp Postgres encode returned IsNull::Yes for ({secs}, {nanos})"
        );

        assert_eq!(
            compat_buf.as_slice(),
            chrono_buf.as_slice(),
            "Postgres binary wire bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            <UtcTimestamp as Encode<'_, Postgres>>::size_hint(&ts),
            ch.pg_hint,
            "Postgres size_hint mismatch for ({secs}, {nanos})"
        );

        let decoded = UtcTimestamp::decode_postgres_binary(&chrono_buf)
            .expect("decode chrono Postgres binary bytes");
        // Verify binary round-trip matches chrono's exact microsecond truncation
        // (including negative durations toward zero around 2000-01-01).
        let expected_micros = i64::from_be_bytes(chrono_buf.as_slice().try_into().unwrap());
        assert_eq!(decoded.to_postgres_micros().unwrap(), expected_micros);
    }

    // Postgres text-protocol TIMESTAMPTZ / TIMESTAMP values, including short
    // offsets (+00, -05), hour:minute offsets (-05:30), and offset-less
    // TIMESTAMP rows.
    let pg_text_cases = [
        "2026-01-02 03:04:05+00",
        "2026-01-02 03:04:05.123456+00",
        "2026-01-02 03:04:05+00:00",
        "2026-01-02 03:04:05.5-05",
        "2026-01-01 21:34:05.123456-05:30",
        "1999-12-31 23:59:59.999999+00",
        "2000-01-01 00:00:00+00",
        "1969-12-31 23:59:59.5-00",
        "2026-01-02 03:04:05",
        "2026-01-02 03:04:05.123456",
    ];

    for raw in pg_text_cases {
        let parsed = parse_postgres_datetime_text(raw)
            .unwrap_or_else(|e| panic!("parse_postgres_datetime_text failed on {raw:?}: {e}"));

        // Compare against chrono's Postgres text parser (`%Y-%m-%d
        // %H:%M:%S%.f%#z` with an offset, `NaiveDateTime` without one).
        let ch_utc = instant_of(oracle().find("pg_text", "i", raw));
        assert_eq!(
            (parsed.unix_timestamp(), parsed.subsec_nanos()),
            ch_utc,
            "raw={raw:?}"
        );
    }

    // Postgres historical offsets with seconds (`±HH:MM:SS`) are also accepted.
    let pg_hms_offset = parse_postgres_datetime_text("2026-01-02 08:34:20.123456+05:30:15")
        .expect("parse Postgres ±HH:MM:SS offset");
    assert_eq!(pg_hms_offset.to_rfc3339_z(), "2026-01-02T03:04:05.123456Z");
}

#[tokio::test]
async fn sqlx_any_roundtrip_matches_chrono_to_rfc3339_and_reads_legacy_rows() {
    sqlx::any::install_default_drivers();
    // SQLite `:memory:` creates an isolated database per connection; limit the
    // AnyPool to 1 connection so DDL and DML share the same in-memory database.
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory AnyPool");

    sqlx::query(
        "CREATE TABLE any_ts_parity (
            id INTEGER PRIMARY KEY,
            compat_ts TEXT NOT NULL,
            chrono_ts TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("create any_ts_parity");

    for (idx, (secs, nanos)) in representative_instants().into_iter().enumerate() {
        let (ts, ch) = pair_for(secs, nanos);

        sqlx::query("INSERT INTO any_ts_parity (id, compat_ts, chrono_ts) VALUES (?, ?, ?)")
            .bind(idx as i64)
            .bind(ts)
            .bind(ch.rfc3339.as_str())
            .execute(&pool)
            .await
            .expect("insert any_ts_parity row");

        let row = sqlx::query("SELECT compat_ts, chrono_ts FROM any_ts_parity WHERE id = ?")
            .bind(idx as i64)
            .fetch_one(&pool)
            .await
            .expect("select any_ts_parity row");

        let compat_raw: String = row.try_get(0).expect("compat_ts as String");
        let chrono_raw: String = row.try_get(1).expect("chrono_ts as String");
        assert_eq!(
            compat_raw.as_bytes(),
            chrono_raw.as_bytes(),
            "sqlx::Any stored text diverged from chrono::to_rfc3339 for ({secs}, {nanos})"
        );

        let decoded_compat: UtcTimestamp = row.try_get(0).expect("decode compat_ts");
        let decoded_chrono: UtcTimestamp = row.try_get(1).expect("decode chrono_ts");
        assert_eq!(decoded_compat, ts);
        assert_eq!(decoded_chrono, ts);
    }

    // Legacy CURRENT_TIMESTAMP row and Z-suffixed row through sqlx::Any.
    for (legacy, expected) in [
        ("2026-01-02 03:04:05", "2026-01-02T03:04:05Z"),
        ("2026-01-02T03:04:05.123Z", "2026-01-02T03:04:05.123Z"),
    ] {
        let row = sqlx::query("SELECT ?")
            .bind(legacy)
            .fetch_one(&pool)
            .await
            .expect("select legacy Any row");
        let decoded: UtcTimestamp = row.try_get(0).expect("decode legacy Any timestamp");
        assert_eq!(decoded.to_rfc3339_z(), expected);
    }
}

/// Phase 3 moved the notification email `Date:` header from chrono's
/// `to_rfc2822()` to `UtcTimestamp::to_rfc2822()`. Pin it byte-for-byte,
/// including the unpadded day of month and four-digit early years, and pin
/// the `None` returned where chrono's formatter would panic.
#[test]
fn rfc2822_formatting_matches_chrono_byte_for_byte() {
    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);
        assert_eq!(
            ts.to_rfc2822().as_deref(),
            Some(ch.rfc2822.as_str()),
            "to_rfc2822 mismatch for ({secs}, {nanos})"
        );
    }

    let fixed: UtcTimestamp = "2026-05-14T10:00:00Z".parse().unwrap();
    assert_eq!(
        fixed.to_rfc2822().as_deref(),
        Some("Thu, 14 May 2026 10:00:00 +0000")
    );

    let year1 = UtcTimestamp::from_utc_date_time(
        Date::from_calendar_date(1, Month::January, 1).unwrap(),
        Time::MIDNIGHT,
    );
    assert_eq!(
        year1.to_rfc2822().as_deref(),
        Some(text(&oracle().misc()["year1_rfc2822"]))
    );
    assert_eq!(
        year1.to_rfc2822().as_deref(),
        Some("Mon, 1 Jan 0001 00:00:00 +0000")
    );

    let negative_year = UtcTimestamp::from_utc_date_time(
        Date::from_calendar_date(-1, Month::December, 31).unwrap(),
        Time::MIDNIGHT,
    );
    assert_eq!(negative_year.to_rfc2822(), None);
}

/// `chrono_try_seconds` replaces `chrono::Duration::try_seconds` in migrated
/// configuration paths (issue #7419) and must accept exactly the same values.
#[test]
fn chrono_try_seconds_accepts_exactly_what_chrono_does() {
    const MAX_SECS: i64 = i64::MAX / 1_000;
    for secs in [
        0,
        1,
        -1,
        86_400,
        MAX_SECS,
        MAX_SECS + 1,
        -MAX_SECS,
        -MAX_SECS - 1,
        i64::MAX,
        i64::MIN,
    ] {
        let ours = ferrum_edge::time_compat::chrono_try_seconds(secs);
        let theirs = &oracle().find("try_seconds", "i", secs)["secs"];
        assert_eq!(
            ours.map(|duration| duration.whole_seconds()),
            theirs.as_i64(),
            "acceptance and value for {secs}"
        );
        assert_eq!(theirs.is_null(), ours.is_none(), "acceptance for {secs}");
    }
}

/// Phase 15 replaced the Lambda `requestContext.time` rendering
/// `format("%d/%b/%Y:%H:%M:%S %z")` with `to_common_log_format()`.
#[test]
fn common_log_format_matches_chrono_strftime() {
    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);
        assert_eq!(ts.to_common_log_format(), ch.clf, "({secs}, {nanos})");
    }
    let fixed: UtcTimestamp = "2026-11-07T08:09:10Z".parse().unwrap();
    assert_eq!(fixed.to_common_log_format(), "07/Nov/2026:08:09:10 +0000");
}

/// Phase 11 replaced `DateTime::from_timestamp_millis(..).unwrap_or(UNIX_EPOCH)`
/// with `UtcTimestamp::from_unix_timestamp_millis(..).unwrap_or(UNIX_EPOCH)`.
/// In range the instant and its RFC 3339 bytes match chrono exactly,
/// including pre-epoch flooring; outside UtcTimestamp's range conversion fails
/// (issue #7419 owner decision) and the caller's fallback applies.
#[test]
fn from_unix_timestamp_millis_matches_chrono_in_range() {
    assert_eq!(
        UtcTimestamp::UNIX_EPOCH.to_rfc3339(),
        text(&oracle().misc()["epoch_rfc3339"])
    );
    for millis in [
        0_i64,
        1,
        -1,
        -999,
        -1_000,
        -1_001,
        999,
        1_767_323_045_123,
        -30_610_224_000_000,
        253_402_300_799_999,
    ] {
        let ours = UtcTimestamp::from_unix_timestamp_millis(millis).expect("in range");
        let theirs = text(&oracle().find("from_millis", "i", millis)["rfc3339"]);
        assert_eq!(ours.to_rfc3339(), theirs, "millis {millis}");
        assert_eq!(ours.unix_timestamp_millis(), millis, "round trip {millis}");
    }
    // Year 10000 is representable in chrono but not in UtcTimestamp.
    assert!(oracle().find("from_millis", "i", 253_402_300_800_000_i64)["rfc3339"].is_string());
    assert_eq!(
        UtcTimestamp::from_unix_timestamp_millis(253_402_300_800_000),
        Err(TimestampError::OutOfRange)
    );
    assert!(oracle().find("from_millis", "i", i64::MIN)["rfc3339"].is_null());
    assert_eq!(
        UtcTimestamp::from_unix_timestamp_millis(i64::MIN),
        Err(TimestampError::OutOfRange)
    );
}
