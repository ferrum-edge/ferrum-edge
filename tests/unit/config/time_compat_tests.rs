//! Byte-for-byte compatibility tests for `ferrum_edge::time_compat` against
//! `chrono::DateTime<chrono::Utc>` across serde, SQLite, MySQL, PostgreSQL,
//! and `sqlx::Any` (issue #7419, Phase 1).

use std::time::{Duration as StdDuration, UNIX_EPOCH};

use chrono::{DateTime, NaiveDateTime, SecondsFormat as ChronoSecondsFormat, Utc};
use ferrum_edge::time_compat::{
    SecondsFormat, TimestampError, UtcTimestamp, decode_sqlite_julian_day,
    parse_mysql_datetime_text, parse_postgres_datetime_text, parse_rfc3339,
    parse_sqlite_datetime_text,
};
use sqlx::any::AnyPoolOptions;
use sqlx::encode::IsNull;
use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType};
use sqlx::{Encode, MySql, Postgres, Row, Sqlite, SqlitePool, Type};
use time::{Date, Month, SignedDuration, Time, UtcOffset};

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

fn pair_for(secs: i64, nanos: u32) -> (UtcTimestamp, DateTime<Utc>) {
    let ts = UtcTimestamp::from_unix_timestamp_nanos(secs, nanos)
        .expect("representative instant valid for UtcTimestamp");
    let ch = DateTime::<Utc>::from_timestamp(secs, nanos)
        .expect("representative instant valid for chrono");
    assert_eq!(ts.unix_timestamp(), ch.timestamp());
    assert_eq!(ts.subsec_nanos(), ch.timestamp_subsec_nanos());
    (ts, ch)
}

#[test]
fn rfc3339_formatting_matches_chrono_byte_for_byte() {
    let modes = [
        (SecondsFormat::Secs, ChronoSecondsFormat::Secs),
        (SecondsFormat::Millis, ChronoSecondsFormat::Millis),
        (SecondsFormat::Micros, ChronoSecondsFormat::Micros),
        (SecondsFormat::Nanos, ChronoSecondsFormat::Nanos),
        (SecondsFormat::AutoSi, ChronoSecondsFormat::AutoSi),
    ];

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        assert_eq!(
            ts.to_rfc3339().as_bytes(),
            ch.to_rfc3339().as_bytes(),
            "to_rfc3339 mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_rfc3339_z().as_bytes(),
            ch.to_rfc3339_opts(ChronoSecondsFormat::AutoSi, true)
                .as_bytes(),
            "to_rfc3339_z mismatch for ({secs}, {nanos})"
        );

        for (ours, theirs) in modes {
            for use_z in [false, true] {
                assert_eq!(
                    ts.to_rfc3339_opts(ours, use_z).as_bytes(),
                    ch.to_rfc3339_opts(theirs, use_z).as_bytes(),
                    "to_rfc3339_opts({ours:?}, {use_z}) mismatch for ({secs}, {nanos})"
                );
            }
        }
    }

    // Year 0001 boundary (valid for RFC 3339 / SQLite / Postgres, outside MySQL 1000..=9999).
    let year1_date = Date::from_calendar_date(1, Month::January, 1).unwrap();
    let year1_ts = UtcTimestamp::from_utc_date_time(year1_date, Time::MIDNIGHT);
    let year1_ch = DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(year1_ts.to_rfc3339(), year1_ch.to_rfc3339());
    assert_eq!(year1_ts.to_rfc3339_z(), "0001-01-01T00:00:00Z");
}

#[test]
fn serde_json_and_yaml_match_chrono_byte_for_byte() {
    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        let ts_json = serde_json::to_string(&ts).expect("serialize UtcTimestamp to JSON");
        let ch_json = serde_json::to_string(&ch).expect("serialize chrono DateTime to JSON");
        assert_eq!(
            ts_json.as_bytes(),
            ch_json.as_bytes(),
            "JSON serialization mismatch for ({secs}, {nanos})"
        );

        // Cross-deserialize JSON written by chrono into UtcTimestamp and vice versa.
        let decoded_ts: UtcTimestamp =
            serde_json::from_str(&ch_json).expect("deserialize chrono JSON into UtcTimestamp");
        assert_eq!(decoded_ts, ts);

        let decoded_ch: DateTime<Utc> =
            serde_json::from_str(&ts_json).expect("deserialize UtcTimestamp JSON into chrono");
        assert_eq!(decoded_ch, ch);

        let ts_yaml = serde_yaml::to_string(&ts).expect("serialize UtcTimestamp to YAML");
        let ch_yaml = serde_yaml::to_string(&ch).expect("serialize chrono DateTime to YAML");
        assert_eq!(
            ts_yaml.as_bytes(),
            ch_yaml.as_bytes(),
            "YAML serialization mismatch for ({secs}, {nanos})"
        );
        let decoded_yaml: UtcTimestamp =
            serde_yaml::from_str(&ch_yaml).expect("deserialize chrono YAML into UtcTimestamp");
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
        let ch: DateTime<Utc> = serde_json::from_str(input).expect("chrono parses input");
        assert_eq!(ts.unix_timestamp(), ch.timestamp(), "input={input}");
        assert_eq!(
            ts.subsec_nanos(),
            ch.timestamp_subsec_nanos(),
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
            ch.timestamp(),
            "unix_timestamp mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.unix_timestamp_millis(),
            ch.timestamp_millis(),
            "unix_timestamp_millis mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_rfc3339_opts(SecondsFormat::Secs, true),
            ch.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "Secs+Z vs strftime mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_compact_date(),
            ch.format("%Y%m%d").to_string(),
            "compact date mismatch for ({secs}, {nanos})"
        );
        assert_eq!(
            ts.to_compact_date_time(),
            ch.format("%Y%m%d%H%M%S").to_string(),
            "compact date-time mismatch for ({secs}, {nanos})"
        );
    }

    // Years outside 0..=9999 get chrono's explicit sign. `UtcTimestamp::now()`
    // reads the wall clock directly, and `time/large-dates` is unified in by
    // bson, so a far-future clock reaches these formatters.
    for year in [-1, 10_000] {
        let Ok(date) = Date::from_calendar_date(year, Month::December, 31) else {
            // Without `time/large-dates` the year is unrepresentable.
            continue;
        };
        let ts = UtcTimestamp::from_utc_date_time(date, Time::from_hms(10, 20, 30).unwrap());
        let ch = DateTime::<Utc>::from_timestamp(ts.unix_timestamp(), 0)
            .expect("chrono represents the instant");
        assert_eq!(ts.to_compact_date(), ch.format("%Y%m%d").to_string());
        assert_eq!(
            ts.to_compact_date_time(),
            ch.format("%Y%m%d%H%M%S").to_string()
        );
    }

    let ts = UtcTimestamp::now();
    let ch = DateTime::<Utc>::from_timestamp(ts.unix_timestamp(), ts.subsec_nanos())
        .expect("current instant valid for chrono");
    assert_eq!(ts.unix_timestamp_millis(), ch.timestamp_millis());
    assert_eq!(ts.to_rfc3339(), ch.to_rfc3339());
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
        <UtcTimestamp as Type<Sqlite>>::type_info(),
        <DateTime<Utc> as Type<Sqlite>>::type_info()
    );

    for (idx, (secs, nanos)) in representative_instants().into_iter().enumerate() {
        let (ts, ch) = pair_for(secs, nanos);

        sqlx::query(
            "INSERT INTO ts_parity (id, dt_compat, dt_chrono, txt_compat, txt_chrono)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(idx as i64)
        .bind(ts)
        .bind(ch)
        .bind(ts)
        .bind(ch)
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
                dt_compat,
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

        assert_eq!(
            dt_compat_bytes, dt_chrono_bytes,
            "SQLite DATETIME bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            txt_compat_bytes, txt_chrono_bytes,
            "SQLite TEXT bytes diverged from chrono for ({secs}, {nanos})"
        );

        // Round-trip both directions: UtcTimestamp reads chrono-written columns
        // and chrono reads UtcTimestamp-written columns.
        let compat_from_compat: UtcTimestamp = row.try_get(4).expect("decode compat from compat");
        let compat_from_chrono: UtcTimestamp = row.try_get(5).expect("decode compat from chrono");
        let chrono_from_compat: DateTime<Utc> = row.try_get(6).expect("decode chrono from compat");
        let compat_from_txt: UtcTimestamp = row.try_get(7).expect("decode compat from chrono text");

        assert_eq!(compat_from_compat, ts);
        assert_eq!(compat_from_chrono, ts);
        assert_eq!(compat_from_txt, ts);
        assert_eq!(chrono_from_compat, ch);
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
        let row = sqlx::query("SELECT ?1, ?1")
            .bind(raw)
            .fetch_one(&pool)
            .await
            .expect("select legacy text");
        let compat_val: UtcTimestamp = row
            .try_get(0)
            .unwrap_or_else(|e| panic!("UtcTimestamp failed on legacy SQLite text {raw:?}: {e}"));
        let chrono_val: DateTime<Utc> = row
            .try_get(1)
            .unwrap_or_else(|e| panic!("chrono failed on legacy SQLite text {raw:?}: {e}"));
        assert_eq!(compat_val.to_rfc3339_z(), expected_rfc3339_z, "raw={raw:?}");
        assert_eq!(
            compat_val.unix_timestamp(),
            chrono_val.timestamp(),
            "raw={raw:?}"
        );
        assert_eq!(
            compat_val.subsec_nanos(),
            chrono_val.timestamp_subsec_nanos(),
            "raw={raw:?}"
        );
        assert_eq!(parse_sqlite_datetime_text(raw).unwrap(), compat_val);
    }

    // Legacy INTEGER Unix seconds (positive, epoch, negative pre-epoch).
    for unix_secs in [1_767_323_045_i64, 0, -86_400] {
        let row = sqlx::query("SELECT ?1, ?1")
            .bind(unix_secs)
            .fetch_one(&pool)
            .await
            .expect("select legacy integer");
        let compat_val: UtcTimestamp = row.try_get(0).expect("decode integer timestamp");
        let chrono_val: DateTime<Utc> = row.try_get(1).expect("chrono decode integer timestamp");
        assert_eq!(compat_val.unix_timestamp(), chrono_val.timestamp());
        assert_eq!(compat_val.subsec_nanos(), 0);
    }

    // Legacy REAL Julian day numbers (pre-epoch and post-epoch).
    for (unix_secs, subsec_nanos) in [(-1_i64, 500_000_000_u32), (1, 500_000_000)] {
        let julian = 2_440_587.5 + (unix_secs as f64 + f64::from(subsec_nanos) / 1e9) / 86_400.0;
        let row = sqlx::query("SELECT ?1, ?1")
            .bind(julian)
            .fetch_one(&pool)
            .await
            .expect("select legacy julian real");
        let compat_val: UtcTimestamp = row.try_get(0).expect("decode julian day");
        let chrono_val: DateTime<Utc> = row.try_get(1).expect("chrono decode julian day");
        let expected = UtcTimestamp::from_unix_timestamp_nanos(unix_secs, subsec_nanos).unwrap();
        let diff_us = (compat_val - expected).whole_microseconds().abs();
        assert!(diff_us < 1_000, "julian diff too large: {diff_us} us");
        assert_eq!(compat_val.unix_timestamp(), chrono_val.timestamp());
        assert!(
            (i64::from(compat_val.subsec_nanos()) - i64::from(chrono_val.timestamp_subsec_nanos()))
                .abs()
                <= 1,
            "julian subsec diverged from chrono"
        );
    }

    // Invalid SQLite text fails closed.
    let bad_row = sqlx::query("SELECT 'not-a-date'")
        .fetch_one(&pool)
        .await
        .expect("select invalid text");
    assert!(bad_row.try_get::<UtcTimestamp, _>(0).is_err());
}

#[test]
fn mysql_binary_wire_encoding_matches_chrono_byte_for_byte_and_decodes_legacy_formats() {
    assert_eq!(
        <UtcTimestamp as Type<MySql>>::type_info(),
        <DateTime<Utc> as Type<MySql>>::type_info()
    );
    assert!(<UtcTimestamp as Type<MySql>>::compatible(
        &<DateTime<Utc> as Type<MySql>>::type_info()
    ));
    assert!(<UtcTimestamp as Type<MySql>>::compatible(
        &<String as Type<MySql>>::type_info()
    ));

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        let mut compat_buf = Vec::new();
        let mut chrono_buf = Vec::new();

        let compat_null = <UtcTimestamp as Encode<'_, MySql>>::encode_by_ref(&ts, &mut compat_buf)
            .expect("encode UtcTimestamp for MySQL");
        let chrono_null = <DateTime<Utc> as Encode<'_, MySql>>::encode_by_ref(&ch, &mut chrono_buf)
            .expect("encode chrono DateTime for MySQL");
        assert!(
            matches!(compat_null, IsNull::No),
            "UtcTimestamp MySQL encode returned IsNull::Yes for ({secs}, {nanos})"
        );
        assert!(
            matches!(chrono_null, IsNull::No),
            "chrono MySQL encode returned IsNull::Yes for ({secs}, {nanos})"
        );

        assert_eq!(
            compat_buf, chrono_buf,
            "MySQL binary wire bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            <UtcTimestamp as Encode<'_, MySql>>::size_hint(&ts),
            <DateTime<Utc> as Encode<'_, MySql>>::size_hint(&ch),
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

        // Cross-check space-separated rows directly against chrono's MySQL text parser.
        if !raw.contains('T') {
            let ch = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f")
                .expect("chrono parses MySQL text")
                .and_utc();
            assert_eq!(parsed.unix_timestamp(), ch.timestamp());
            assert_eq!(parsed.subsec_nanos(), ch.timestamp_subsec_nanos());
        }
    }
}

#[test]
fn postgres_binary_and_text_wire_formats_match_chrono_byte_for_byte() {
    assert_eq!(
        <UtcTimestamp as Type<Postgres>>::type_info(),
        <DateTime<Utc> as Type<Postgres>>::type_info()
    );
    assert_eq!(
        <UtcTimestamp as PgHasArrayType>::array_type_info(),
        <DateTime<Utc> as PgHasArrayType>::array_type_info()
    );
    assert!(<UtcTimestamp as Type<Postgres>>::compatible(
        &<DateTime<Utc> as Type<Postgres>>::type_info()
    ));
    assert!(<UtcTimestamp as Type<Postgres>>::compatible(
        &<String as Type<Postgres>>::type_info()
    ));

    for (secs, nanos) in representative_instants() {
        let (ts, ch) = pair_for(secs, nanos);

        let mut compat_buf = PgArgumentBuffer::default();
        let mut chrono_buf = PgArgumentBuffer::default();

        let compat_null =
            <UtcTimestamp as Encode<'_, Postgres>>::encode_by_ref(&ts, &mut compat_buf)
                .expect("encode UtcTimestamp for Postgres");
        let chrono_null =
            <DateTime<Utc> as Encode<'_, Postgres>>::encode_by_ref(&ch, &mut chrono_buf)
                .expect("encode chrono DateTime for Postgres");
        assert!(
            matches!(compat_null, IsNull::No),
            "UtcTimestamp Postgres encode returned IsNull::Yes for ({secs}, {nanos})"
        );
        assert!(
            matches!(chrono_null, IsNull::No),
            "chrono Postgres encode returned IsNull::Yes for ({secs}, {nanos})"
        );

        assert_eq!(
            compat_buf.as_slice(),
            chrono_buf.as_slice(),
            "Postgres binary wire bytes diverged from chrono for ({secs}, {nanos})"
        );
        assert_eq!(
            <UtcTimestamp as Encode<'_, Postgres>>::size_hint(&ts),
            <DateTime<Utc> as Encode<'_, Postgres>>::size_hint(&ch),
            "Postgres size_hint mismatch for ({secs}, {nanos})"
        );

        let decoded = UtcTimestamp::decode_postgres_binary(chrono_buf.as_slice())
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

        // Compare against chrono's Postgres text parser.
        let ch_utc = if raw.len() > 19 && (raw[19..].contains('+') || raw[19..].contains('-')) {
            DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f%#z")
                .unwrap_or_else(|e| panic!("chrono failed on Postgres text {raw:?}: {e}"))
                .with_timezone(&Utc)
        } else {
            NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f")
                .unwrap_or_else(|e| panic!("chrono failed on Postgres naive text {raw:?}: {e}"))
                .and_utc()
        };

        assert_eq!(parsed.unix_timestamp(), ch_utc.timestamp(), "raw={raw:?}");
        assert_eq!(
            parsed.subsec_nanos(),
            ch_utc.timestamp_subsec_nanos(),
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
            .bind(ch.to_rfc3339())
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
            Some(ch.to_rfc2822().as_str()),
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
    let year1_ch = DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(year1.to_rfc2822(), Some(year1_ch.to_rfc2822()));
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

/// Phase 11 replaced `DateTime::from_timestamp_millis(..).unwrap_or(UNIX_EPOCH)`
/// with `UtcTimestamp::from_unix_timestamp_millis(..).unwrap_or(UNIX_EPOCH)`.
/// In range the instant and its RFC 3339 bytes match chrono exactly,
/// including pre-epoch flooring; outside UtcTimestamp's range conversion fails
/// (issue #7419 owner decision) and the caller's fallback applies.
#[test]
fn from_unix_timestamp_millis_matches_chrono_in_range() {
    assert_eq!(
        UtcTimestamp::UNIX_EPOCH.to_rfc3339(),
        DateTime::<Utc>::UNIX_EPOCH.to_rfc3339()
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
        let theirs = DateTime::<Utc>::from_timestamp_millis(millis).expect("chrono in range");
        assert_eq!(ours.to_rfc3339(), theirs.to_rfc3339(), "millis {millis}");
        assert_eq!(ours.unix_timestamp_millis(), millis, "round trip {millis}");
    }
    // Year 10000 is representable in chrono but not in UtcTimestamp.
    assert!(DateTime::<Utc>::from_timestamp_millis(253_402_300_800_000).is_some());
    assert_eq!(
        UtcTimestamp::from_unix_timestamp_millis(253_402_300_800_000),
        Err(TimestampError::OutOfRange)
    );
    assert_eq!(
        UtcTimestamp::from_unix_timestamp_millis(i64::MIN),
        Err(TimestampError::OutOfRange)
    );
}
