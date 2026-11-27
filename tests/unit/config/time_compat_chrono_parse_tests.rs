//! Accept/reject parity corpus for the chrono-compatible parsers in
//! `ferrum_edge::time_compat` (issue #7419). Every input runs through chrono
//! 0.4.45 and through the `time_compat` port; both must accept or both must
//! reject, and accepted inputs must yield the same instant, sub-second part
//! (including chrono's leap-second representation), offset and local fields.
//!
//! chrono stays as the oracle here until the dependency-retirement phase.

use chrono::{DateTime, Datelike, FixedOffset, NaiveDateTime, Timelike};
use ferrum_edge::time_compat::{
    ChronoParsedDateTime, TimestampError, UtcTimestamp, parse_from_str_chrono,
    parse_naive_from_str_chrono, parse_rfc2822_chrono, parse_rfc3339_chrono,
    parse_rfc3339_relaxed_chrono,
};

/// The strftime formats Ferrum parses with chrono today.
const OFFSET_FORMATS: &[&str] = &[
    // soap_ws_security (the `...Z` forms carry no offset item, so chrono
    // always refuses them; parity must hold for that too).
    "%Y-%m-%dT%H:%M:%S%.fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%.f%:z",
    "%Y-%m-%dT%H:%M:%S%:z",
    // Remaining supported specifiers and padding flags.
    "%Y-%m-%dT%H:%M:%S%z",
    "%d %B %Y %H:%M:%S%.f %:z",
    "%-d %h %Y %_H:%0M:%S %z",
];
const NAIVE_FORMATS: &[&str] = &[
    // response_caching HTTP-date fallbacks.
    "%a, %d %b %Y %H:%M:%S GMT",
    "%A, %d-%b-%y %H:%M:%S GMT",
    "%a %b %e %H:%M:%S %Y",
    // db_loader legacy CURRENT_TIMESTAMP rows.
    "%Y-%m-%d %H:%M:%S",
    // A naive parse validates but ignores the offset (even an out-of-range one).
    "%Y-%m-%dT%H:%M:%S%z",
    // `%Y` and `%y` must agree; a fraction without `%S` is refused, but
    // `%.f` is optional so minute-only input still resolves.
    "%Y/%y %m %d %H:%M",
    "%Y-%m-%d %H:%M%.f",
    "%%%Y-%m-%d %H:%M:%S",
    "%e %B %Y %H:%M:%S",
];

const BASES: &[&str] = &[
    // RFC 3339, strict and relaxed shapes.
    "2026-11-26T10:20:30Z",
    "2026-11-26t10:20:30.123456789z",
    "2026-11-26 10:20:30+05:30",
    "2026-11-26T10:20:30.1-00:00",
    "1999-12-31T23:59:60Z",
    "1999-12-31T23:59:60.5-01:00",
    "2026-11-26T12:30:60+01:00",
    "0000-01-01T00:00:00+23:59",
    "9999-12-31T23:59:59.99999999999\u{2212}00:30",
    "2024-02-29T12:00:00Z",
    "2023-02-29T12:00:00Z",
    "2026-11-26T24:00:00Z",
    "2026-11-26T10:20:30+24:00",
    "+12345-01-01T00:00:00Z",
    "-0001-12-31T23:59:59Z",
    "-262143-01-01T00:00:00+00:01",
    "-262143-01-01T00:00:00-00:01",
    "+262142-12-31T23:59:59-00:01",
    "2026-1-2T3:4:5Z",
    "2026-11-26T10:20:30 UTC",
    "2026-11-26T10:20:30+0530",
    "2026-11-26T10:20:30 +05 30",
    " 2026 - 11 - 26 T10 : 20 : 30.5 Z ",
    "2026-11-26T10:20:30.Z",
    "2026-11-26T10:20:30,5Z",
    // RFC 2822.
    "Thu, 26 Nov 2026 10:20:30 GMT",
    "26 Nov 2026 10:20 +0530",
    "Wed, 26 Nov 2026 10:20:30 GMT",
    "Thu, 26 Nov 26 10:20:30 EST",
    "Sun, 06 Nov 94 08:49:37 GMT",
    "6 Nov 994 08:49:37 Z",
    "Thu,26 Nov 2026 10 : 20:30 -0000 (comment (nested) \\) x)",
    "Thu, 26 Nov 2026 23:59:60 +2359",
    "Mon, 26 Nov 12345 10:20:30 a",
    "Mon, 1 Jan 0001 00:00:00 +9959",
    // chrono's year limits: applying the offset can push UTC outside them.
    "Mon, 31 Dec 262142 23:59:59 -2359",
    "Mon, 31 Dec 262142 23:59:59 +2359",
    "Thu, 26 nov 2026 10:20:30 pdt",
    "Thu, 26 Nov 2026 10:20:30 J",
    // HTTP-date fallbacks and legacy SQL text.
    "Sun, 06 Nov 1994 08:49:37 GMT",
    "Sunday, 06-Nov-94 08:49:37 GMT",
    "Sun Nov  6 08:49:37 1994",
    "Sun Nov 6 08:49:37 1994",
    "Mon Nov  6 08:49:37 1994",
    "2026-11-26 10:20:30",
    "2026-1-2 3:4:5",
    // WS-Security.
    "2026-11-26T10:20:30.5+05:30",
    "2026-11-26T10:20:30+05:30",
    // Extra strftime specifier coverage.
    "2026-11-26T10:20:30+9959",
    "26 November 2026 10:20:30.5 +05:30",
    "26 Nov 2026 10:20:30 +0530",
    "2026/26 11 26 10:20",
    "2026/27 11 26 10:20",
    "-2026/26 11 26 10:20",
    "2026-11-26 10:20.5",
    "2026-11-26 10:20",
    "%2026-11-26 10:20:30",
    "26 november 2026 10:20:30",
];

const PALETTE: &[char] = &[
    '0', '1', '5', '6', '9', ' ', '\t', '\u{a0}', 'T', 't', 'Z', 'z', '+', '-', '\u{2212}', ':',
    '.', 'x', '(', ')', '\\', ',', 'G', 'U', 'C', 'a', '\u{e9}',
];

/// Single-character deletions, substitutions and insertions of every base.
fn corpus() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.push(String::new());
    for base in BASES {
        let chars: Vec<char> = base.chars().collect();
        out.push((*base).to_string());
        for i in 0..=chars.len() {
            if i < chars.len() {
                let mut deleted = chars.clone();
                deleted.remove(i);
                out.push(deleted.into_iter().collect());
            }
            for &p in PALETTE {
                if i < chars.len() {
                    let mut replaced = chars.clone();
                    replaced[i] = p;
                    out.push(replaced.into_iter().collect());
                }
                let mut inserted = chars.clone();
                inserted.insert(i, p);
                out.push(inserted.into_iter().collect());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn assert_fixed_parity(
    what: &str,
    input: &str,
    ours: Result<ChronoParsedDateTime, TimestampError>,
    theirs: chrono::ParseResult<DateTime<FixedOffset>>,
) -> bool {
    match (ours, theirs) {
        (Ok(o), Ok(t)) => {
            let n = t.naive_local();
            assert_eq!(
                o.unix_timestamp_nanos_opt(),
                t.timestamp_nanos_opt(),
                "{what}: timestamp_nanos_opt mismatch for {input:?}"
            );
            assert_eq!(
                (
                    o.unix_timestamp(),
                    o.nanosecond(),
                    o.offset_seconds(),
                    o.unix_timestamp_millis()
                ),
                (
                    t.timestamp(),
                    t.timestamp_subsec_nanos(),
                    t.offset().local_minus_utc(),
                    t.timestamp_millis()
                ),
                "{what}: instant mismatch for {input:?}"
            );
            assert_eq!(
                (
                    o.year(),
                    u32::from(o.month()),
                    u32::from(o.day()),
                    u32::from(o.hour()),
                    u32::from(o.minute()),
                    u32::from(o.second()),
                ),
                (
                    n.year(),
                    n.month(),
                    n.day(),
                    n.hour(),
                    n.minute(),
                    n.second()
                ),
                "{what}: local field mismatch for {input:?}"
            );
            assert_utc_conversion(
                what,
                input,
                &o,
                t.timestamp_nanos_opt(),
                t.timestamp_millis(),
            );
            true
        }
        (Err(_), Err(_)) => false,
        (Ok(o), Err(e)) => panic!("{what}: time_compat accepted {input:?} as {o:?}; chrono: {e}"),
        (Err(e), Ok(t)) => panic!("{what}: chrono accepted {input:?} as {t:?}; time_compat: {e}"),
    }
}

fn assert_naive_parity(
    what: &str,
    input: &str,
    ours: Result<ChronoParsedDateTime, TimestampError>,
    theirs: chrono::ParseResult<NaiveDateTime>,
) -> bool {
    match (ours, theirs) {
        (Ok(o), Ok(t)) => {
            assert_eq!(o.offset_seconds(), 0, "{what}: naive offset for {input:?}");
            assert_eq!(
                (
                    o.unix_timestamp(),
                    o.nanosecond(),
                    o.year(),
                    u32::from(o.month()),
                    u32::from(o.day()),
                    u32::from(o.hour()),
                    u32::from(o.minute()),
                    u32::from(o.second()),
                ),
                (
                    t.and_utc().timestamp(),
                    t.nanosecond(),
                    t.year(),
                    t.month(),
                    t.day(),
                    t.hour(),
                    t.minute(),
                    t.second(),
                ),
                "{what}: naive mismatch for {input:?}"
            );
            let utc = t.and_utc();
            assert_utc_conversion(
                what,
                input,
                &o,
                utc.timestamp_nanos_opt(),
                utc.timestamp_millis(),
            );
            true
        }
        (Err(_), Err(_)) => false,
        (Ok(o), Err(e)) => panic!("{what}: time_compat accepted {input:?} as {o:?}; chrono: {e}"),
        (Err(e), Ok(t)) => panic!("{what}: chrono accepted {input:?} as {t:?}; time_compat: {e}"),
    }
}

/// `to_utc_timestamp` must be exact where `UtcTimestamp` can represent the
/// value, normalize a leap second to chrono's next-second linear instant
/// (#7419 owner decision: millis and nanos equal chrono's), and refuse
/// out-of-range years.
fn assert_utc_conversion(
    what: &str,
    input: &str,
    parsed: &ChronoParsedDateTime,
    chrono_nanos: Option<i64>,
    chrono_millis: i64,
) {
    let converted = parsed.to_utc_timestamp();
    let expected = if parsed.is_leap_second() {
        UtcTimestamp::from_unix_timestamp_nanos(
            parsed.unix_timestamp() + 1,
            parsed.nanosecond() - 1_000_000_000,
        )
    } else {
        UtcTimestamp::from_unix_timestamp_nanos(parsed.unix_timestamp(), parsed.nanosecond())
    };
    match expected {
        Ok(expected) => {
            assert_eq!(converted, Ok(expected), "{what}: conversion for {input:?}");
            assert_eq!(
                expected.unix_timestamp_millis(),
                chrono_millis,
                "{what}: converted millis differ from chrono for {input:?}"
            );
            if let Some(nanos) = chrono_nanos {
                assert_eq!(
                    expected.unix_timestamp_nanos(),
                    i128::from(nanos),
                    "{what}: converted nanos differ from chrono for {input:?}"
                );
            }
        }
        Err(_) => assert!(
            converted.is_err(),
            "{what}: out-of-range conversion for {input:?}"
        ),
    }
}

#[test]
fn chrono_compatible_parsers_match_chrono_on_the_mutation_corpus() {
    let corpus = corpus();
    assert!(
        corpus.len() > 20_000,
        "corpus unexpectedly small: {}",
        corpus.len()
    );

    let mut accepted = [0usize; 3];
    let mut accepted_formats = vec![0usize; OFFSET_FORMATS.len() + NAIVE_FORMATS.len()];
    for input in &corpus {
        let input = input.as_str();
        accepted[0] += usize::from(assert_fixed_parity(
            "rfc3339",
            input,
            parse_rfc3339_chrono(input),
            DateTime::parse_from_rfc3339(input),
        ));
        accepted[1] += usize::from(assert_fixed_parity(
            "rfc3339-relaxed",
            input,
            parse_rfc3339_relaxed_chrono(input),
            input.parse::<DateTime<FixedOffset>>(),
        ));
        accepted[2] += usize::from(assert_fixed_parity(
            "rfc2822",
            input,
            parse_rfc2822_chrono(input),
            DateTime::parse_from_rfc2822(input),
        ));
        for (i, fmt) in OFFSET_FORMATS.iter().enumerate() {
            accepted_formats[i] += usize::from(assert_fixed_parity(
                fmt,
                input,
                parse_from_str_chrono(input, fmt),
                DateTime::parse_from_str(input, fmt),
            ));
        }
        for (i, fmt) in NAIVE_FORMATS.iter().enumerate() {
            accepted_formats[OFFSET_FORMATS.len() + i] += usize::from(assert_naive_parity(
                fmt,
                input,
                parse_naive_from_str_chrono(input, fmt),
                NaiveDateTime::parse_from_str(input, fmt),
            ));
        }
    }

    // Guard against a vacuous corpus: every parser must accept a meaningful
    // number of inputs (the two `...Z` soap formats never can).
    for (name, count) in ["rfc3339", "rfc3339-relaxed", "rfc2822"]
        .iter()
        .zip(accepted)
    {
        assert!(count > 200, "{name} accepted only {count} corpus inputs");
    }
    for (i, count) in accepted_formats.iter().enumerate() {
        let fmt = OFFSET_FORMATS
            .iter()
            .chain(NAIVE_FORMATS)
            .nth(i)
            .copied()
            .unwrap_or_default();
        if fmt.ends_with('Z') {
            assert_eq!(
                *count, 0,
                "{fmt} has no offset item; chrono never accepts it"
            );
        } else {
            assert!(*count > 20, "{fmt} accepted only {count} corpus inputs");
        }
    }
}

/// The three behaviours the owner called out explicitly (#7419).
#[test]
fn rfc3339_leap_second_unicode_minus_and_signed_years_follow_chrono() {
    // Leap second at any minute, kept as second 59 + 1e9 nanoseconds.
    let leap = parse_rfc3339_chrono("2026-11-26T12:30:60.25+01:00").expect("leap second");
    assert!(leap.is_leap_second());
    assert_eq!(leap.second(), 59);
    assert_eq!(leap.nanosecond(), 1_250_000_000);
    let chrono_leap = DateTime::parse_from_rfc3339("2026-11-26T12:30:60.25+01:00").unwrap();
    assert_eq!(leap.unix_timestamp(), chrono_leap.timestamp());
    assert_eq!(leap.unix_timestamp_millis(), chrono_leap.timestamp_millis());
    // Normalized to the next-second instant (owner decision, see below).
    assert_eq!(
        leap.to_utc_timestamp().map(|ts| ts.to_rfc3339_z()),
        Ok("2026-11-26T11:31:00.250Z".to_string())
    );

    // Unicode minus sign in the offset.
    let minus = parse_rfc3339_chrono("2026-11-26T10:20:30\u{2212}05:30").expect("U+2212 offset");
    assert_eq!(minus.offset_seconds(), -(5 * 3_600 + 30 * 60));
    assert!(DateTime::parse_from_rfc3339("2026-11-26T10:20:30\u{2212}05:30").is_ok());

    // Signed or expanded years are refused by the strict parser, as chrono does.
    for input in [
        "+2026-11-26T10:20:30Z",
        "-2026-11-26T10:20:30Z",
        "12026-11-26T10:20:30Z",
        "+012026-11-26T10:20:30Z",
    ] {
        assert!(parse_rfc3339_chrono(input).is_err(), "{input:?}");
        assert!(DateTime::parse_from_rfc3339(input).is_err(), "{input:?}");
    }

    // The existing strict `parse_rfc3339` is unchanged: it still differs on
    // exactly these inputs, which is why parse sites must use the chrono port.
    assert!(ferrum_edge::time_compat::parse_rfc3339("2026-11-26T12:30:60Z").is_err());
}

#[test]
fn http_date_forms_used_by_response_caching_and_hmac_auth_follow_chrono() {
    let imf = parse_rfc2822_chrono("Sun, 06 Nov 1994 08:49:37 GMT").expect("IMF-fixdate");
    assert_eq!(imf.unix_timestamp(), 784_111_777);
    let rfc850 = parse_naive_from_str_chrono(
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
    )
    .expect("RFC 850");
    assert_eq!(rfc850.unix_timestamp(), 784_111_777);
    let asctime = parse_naive_from_str_chrono("Sun Nov  6 08:49:37 1994", "%a %b %e %H:%M:%S %Y")
        .expect("asctime");
    assert_eq!(asctime.unix_timestamp(), 784_111_777);

    // A weekday that contradicts the date is refused by both.
    assert!(parse_rfc2822_chrono("Mon, 06 Nov 1994 08:49:37 GMT").is_err());
    assert!(DateTime::parse_from_rfc2822("Mon, 06 Nov 1994 08:49:37 GMT").is_err());

    // Unsupported specifiers are refused rather than parsed differently.
    assert_eq!(
        parse_naive_from_str_chrono("1994", "%G"),
        Err(TimestampError::InvalidFormat)
    );
}

/// Branches the mutation corpus could otherwise leave untested in both
/// directions: chrono's UTC range check after the offset, a naive parse that
/// ignores an out-of-range offset, `%Y`/`%y` agreement, and padded
/// non-numeric specifiers.
#[test]
fn boundary_and_specifier_cases_follow_chrono() {
    let fixed_cases: &[(&str, Option<&str>)] = &[
        ("Mon, 31 Dec 262142 23:59:59 -2359", None),
        ("Mon, 31 Dec 262142 23:59:59 +2359", None),
        ("-262143-01-01T00:00:00+00:01", None),
        ("-262143-01-01T00:00:00-00:01", None),
        ("2026-11-26T10:20:30+9959", Some("%Y-%m-%dT%H:%M:%S%z")),
        (
            "26 November 2026 10:20:30.5 +05:30",
            Some("%d %B %Y %H:%M:%S%.f %:z"),
        ),
        (
            "26 Nov 2026 10:20:30 +0530",
            Some("%-d %h %Y %_H:%0M:%S %z"),
        ),
        ("26 Nov 2026 10:20:30 +0530", Some("%-d %-h %Y %H:%M:%S %z")),
        ("2026-11-26 10:20:30 +0530", Some("%Y-%m-%d %H:%M:%S %-z")),
    ];
    for (input, fmt) in fixed_cases {
        match fmt {
            None => {
                assert_fixed_parity(
                    "rfc2822",
                    input,
                    parse_rfc2822_chrono(input),
                    DateTime::parse_from_rfc2822(input),
                );
                assert_fixed_parity(
                    "rfc3339-relaxed",
                    input,
                    parse_rfc3339_relaxed_chrono(input),
                    input.parse::<DateTime<FixedOffset>>(),
                );
            }
            Some(fmt) => {
                assert_fixed_parity(
                    fmt,
                    input,
                    parse_from_str_chrono(input, fmt),
                    DateTime::parse_from_str(input, fmt),
                );
            }
        }
    }
    // The UTC range check is what rejects these; the local dates are valid.
    assert!(parse_rfc2822_chrono("Mon, 31 Dec 262142 23:59:59 -2359").is_err());
    assert!(parse_rfc2822_chrono("Mon, 31 Dec 262142 23:59:59 +2359").is_ok());
    assert!(parse_rfc3339_relaxed_chrono("-262143-01-01T00:00:00+00:01").is_err());
    assert!(parse_rfc3339_relaxed_chrono("-262143-01-01T00:00:00-00:01").is_ok());

    let naive_cases: &[(&str, &str)] = &[
        ("2026-11-26T10:20:30+9959", "%Y-%m-%dT%H:%M:%S%z"),
        ("2026/26 11 26 10:20", "%Y/%y %m %d %H:%M"),
        ("2026/27 11 26 10:20", "%Y/%y %m %d %H:%M"),
        ("-2026/26 11 26 10:20", "%Y/%y %m %d %H:%M"),
        ("2026-11-26 10:20.5", "%Y-%m-%d %H:%M%.f"),
        ("%2026-11-26 10:20:30", "%%%Y-%m-%d %H:%M:%S"),
        ("26 november 2026 10:20:30", "%e %B %Y %H:%M:%S"),
        ("Thu 26 Nov 2026 10:20:30", "%-a %d %b %Y %H:%M:%S"),
        ("2026-11-26 10:20:30.5", "%Y-%m-%d %H:%M:%S%-.f"),
        ("2026-11-26 10:20:30", "%Y-%m-%d %H:%M:%-%"),
    ];
    for (input, fmt) in naive_cases {
        assert_naive_parity(
            fmt,
            input,
            parse_naive_from_str_chrono(input, fmt),
            NaiveDateTime::parse_from_str(input, fmt),
        );
    }
    assert!(parse_naive_from_str_chrono("2026-11-26T10:20:30+9959", "%Y-%m-%dT%H:%M:%S%z").is_ok());
    assert!(parse_from_str_chrono("2026-11-26T10:20:30+9959", "%Y-%m-%dT%H:%M:%S%z").is_err());
    assert!(parse_naive_from_str_chrono("2026/26 11 26 10:20", "%Y/%y %m %d %H:%M").is_ok());
    assert!(parse_naive_from_str_chrono("2026/27 11 26 10:20", "%Y/%y %m %d %H:%M").is_err());
    assert!(parse_naive_from_str_chrono("2026-11-26 10:20.5", "%Y-%m-%d %H:%M%.f").is_err());
    assert!(parse_naive_from_str_chrono("2026-11-26 10:20", "%Y-%m-%d %H:%M%.f").is_ok());
}

/// #7419 owner decision (option B): a parsed leap second is stored as the
/// next-second instant chrono's `timestamp_nanos_opt()` reports. Millis and
/// nanos equal chrono's; the formatting, whole-second and in-window ordering
/// differences below are known and accepted, and pinned here so they stay
/// deliberate.
#[test]
fn leap_second_normalization_matches_chrono_nanos_and_documents_differences() {
    let input = "1999-12-31T23:59:60.5Z";
    let chrono_leap = DateTime::parse_from_rfc3339(input).unwrap().to_utc();
    let stored = parse_rfc3339_chrono(input)
        .and_then(|parsed| parsed.to_utc_timestamp())
        .expect("leap second normalizes");

    // Equal to chrono.
    assert_eq!(
        stored.unix_timestamp_nanos(),
        i128::from(chrono_leap.timestamp_nanos_opt().unwrap())
    );
    assert_eq!(
        stored.unix_timestamp_millis(),
        chrono_leap.timestamp_millis()
    );
    let before = DateTime::parse_from_rfc3339("1999-12-31T23:59:59.999999999Z")
        .unwrap()
        .to_utc();
    let after = DateTime::parse_from_rfc3339("2000-01-01T00:00:01Z")
        .unwrap()
        .to_utc();
    let as_stored = |dt: DateTime<chrono::Utc>| {
        UtcTimestamp::from_unix_timestamp_nanos(dt.timestamp(), dt.timestamp_subsec_nanos())
            .unwrap()
    };
    assert_eq!(stored.cmp(&as_stored(before)), chrono_leap.cmp(&before));
    assert_eq!(stored.cmp(&as_stored(after)), chrono_leap.cmp(&after));

    // Known, accepted differences.
    assert_eq!(chrono_leap.to_rfc3339(), "1999-12-31T23:59:60.500+00:00");
    assert_eq!(stored.to_rfc3339(), "2000-01-01T00:00:00.500+00:00");
    assert_eq!(stored.unix_timestamp(), chrono_leap.timestamp() + 1);
    let inside_window = DateTime::parse_from_rfc3339("2000-01-01T00:00:00.25Z")
        .unwrap()
        .to_utc();
    assert_eq!(chrono_leap.cmp(&inside_window), std::cmp::Ordering::Less);
    assert_eq!(
        stored.cmp(&as_stored(inside_window)),
        std::cmp::Ordering::Greater
    );

    // Non-leap values are untouched.
    let plain = parse_rfc3339_chrono("1999-12-31T23:59:59.5Z")
        .and_then(|parsed| parsed.to_utc_timestamp())
        .unwrap();
    assert_eq!(plain.to_rfc3339(), "1999-12-31T23:59:59.500+00:00");
}

/// #7419 owner decision (option B for out-of-range years): chrono accepts
/// these, the ports accept them identically, and conversion to
/// `UtcTimestamp` refuses them because their UTC instant lies outside
/// `-9999..=9999`.
#[test]
fn year_boundary_inputs_parse_like_chrono_but_do_not_convert() {
    let strict = "9999-12-31T23:30:00-01:00";
    assert!(DateTime::parse_from_rfc3339(strict).is_ok());
    let parsed = parse_rfc3339_chrono(strict).expect("strict RFC 3339 accepts");
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    let rfc2822 = "Mon, 26 Nov 12345 10:20:30 GMT";
    assert!(DateTime::parse_from_rfc2822(rfc2822).is_ok());
    let parsed = parse_rfc2822_chrono(rfc2822).expect("RFC 2822 accepts");
    assert_eq!(parsed.year(), 12345);
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    let relaxed = "+12345-01-01T00:00:00Z";
    assert!(relaxed.parse::<DateTime<FixedOffset>>().is_ok());
    let parsed = parse_rfc3339_relaxed_chrono(relaxed).expect("relaxed RFC 3339 accepts");
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    // The nearest in-range neighbours still convert.
    assert!(
        parse_rfc3339_chrono("9999-12-31T23:30:00+00:00")
            .and_then(|parsed| parsed.to_utc_timestamp())
            .is_ok()
    );
}
