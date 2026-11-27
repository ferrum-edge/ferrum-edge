//! Accept/reject parity corpus for the chrono-compatible parsers in
//! `ferrum_edge::time_compat` (issue #7419). Every input runs through the
//! `time_compat` port and is compared with chrono 0.4.45's result for the same
//! input, recorded once from chrono itself in
//! `tests/fixtures/time_compat/chrono_0_4_45_parse_oracle.jsonl` (chrono is no
//! longer a dependency). Both must accept or both must reject, and accepted
//! inputs must yield the same instant, sub-second part (including chrono's
//! leap-second representation), offset and local fields.
//!
//! Fixture lines are JSON objects keyed by `"k"`:
//! - `meta`: corpus size, its FNV-1a 64 digest (each input followed by `\n`)
//!   and the format lists the rows were recorded with.
//! - `c`: a corpus input chrono accepted with at least one parser. Corpus
//!   inputs without a `c` line were rejected by every parser.
//! - `x`: an input outside the corpus that a targeted test below uses.
//! - `f`: an input parsed with a strftime format outside the shared lists.
//! - `leap`: chrono's rendering and ordering of a parsed leap second.
//!
//! A `c`/`x` row holds one entry per parser, `null` where chrono refused: the
//! strict RFC 3339, relaxed RFC 3339 (`FromStr` for `DateTime<FixedOffset>`)
//! and RFC 2822 parsers, then each of `OFFSET_FORMATS`
//! (`DateTime::parse_from_str`), each of `NAIVE_FORMATS`
//! (`NaiveDateTime::parse_from_str`), and last `FromStr` for `DateTime<Utc>`
//! (which chrono's serde `Deserialize` matched on every input). Offset rows are
//! `[timestamp, timestamp_subsec_nanos, offset_seconds, timestamp_nanos_opt,
//! timestamp_millis, local year, month, day, hour, minute, second]`; naive rows
//! are `[UTC timestamp, nanosecond, year, month, day, hour, minute, second, UTC
//! timestamp_nanos_opt, UTC timestamp_millis]`; `DateTime<Utc>` rows are
//! `[timestamp, timestamp_subsec_nanos, timestamp_nanos_opt, timestamp_millis,
//! year of the instant with a leap second moved to the next second, or
//! i32::MAX past chrono's own range]`.

use std::collections::HashMap;
use std::sync::OnceLock;

use ferrum_edge::time_compat::{
    ChronoParsedDateTime, TimestampError, UtcTimestamp, parse_from_str_chrono,
    parse_naive_from_str_chrono, parse_rfc2822_chrono, parse_rfc3339_chrono,
    parse_rfc3339_relaxed_chrono,
};
use serde_json::Value;

const ORACLE_JSONL: &str =
    include_str!("../../fixtures/time_compat/chrono_0_4_45_parse_oracle.jsonl");

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

/// FNV-1a 64 over every corpus input followed by `\n`; pins the corpus the
/// oracle rows were recorded from.
fn corpus_digest(corpus: &[String]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for input in corpus {
        for byte in input.as_bytes().iter().chain(std::iter::once(&b'\n')) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

const RFC3339: usize = 0;
const RFC3339_RELAXED: usize = 1;
const RFC2822: usize = 2;
const FIRST_OFFSET_FORMAT: usize = 3;
const FIRST_NAIVE_FORMAT: usize = FIRST_OFFSET_FORMAT + OFFSET_FORMATS.len();
const UTC_FROM_STR: usize = FIRST_NAIVE_FORMAT + NAIVE_FORMATS.len();
const ROW_LEN: usize = UTC_FROM_STR + 1;

/// chrono's `DateTime<FixedOffset>` result.
#[derive(Debug, Clone, Copy)]
struct FixedRecord {
    timestamp: i64,
    subsec_nanos: u32,
    offset_seconds: i32,
    nanos: Option<i64>,
    millis: i64,
    local: (i32, u32, u32, u32, u32, u32),
}

/// chrono's `NaiveDateTime` result (UTC values via `and_utc()`).
#[derive(Debug, Clone, Copy)]
struct NaiveRecord {
    timestamp: i64,
    nanosecond: u32,
    fields: (i32, u32, u32, u32, u32, u32),
    nanos: Option<i64>,
    millis: i64,
}

/// chrono's `DateTime<Utc>` `FromStr` result.
#[derive(Debug, Clone, Copy)]
struct UtcRecord {
    timestamp: i64,
    subsec_nanos: u32,
    nanos: Option<i64>,
    millis: i64,
    normalized_year: i32,
}

fn int(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("oracle value {value} is not an integer"))
}

fn opt_int(value: &Value) -> Option<i64> {
    if value.is_null() {
        None
    } else {
        Some(int(value))
    }
}

fn small<T: TryFrom<i64>>(value: &Value) -> T {
    T::try_from(int(value)).unwrap_or_else(|_| panic!("oracle value {value} out of range"))
}

fn fixed_record(value: &Value) -> Option<FixedRecord> {
    let v = value.as_array()?;
    assert_eq!(v.len(), 11, "offset row {value}");
    Some(FixedRecord {
        timestamp: int(&v[0]),
        subsec_nanos: small(&v[1]),
        offset_seconds: small(&v[2]),
        nanos: opt_int(&v[3]),
        millis: int(&v[4]),
        local: (
            small(&v[5]),
            small(&v[6]),
            small(&v[7]),
            small(&v[8]),
            small(&v[9]),
            small(&v[10]),
        ),
    })
}

fn naive_record(value: &Value) -> Option<NaiveRecord> {
    let v = value.as_array()?;
    assert_eq!(v.len(), 10, "naive row {value}");
    Some(NaiveRecord {
        timestamp: int(&v[0]),
        nanosecond: small(&v[1]),
        fields: (
            small(&v[2]),
            small(&v[3]),
            small(&v[4]),
            small(&v[5]),
            small(&v[6]),
            small(&v[7]),
        ),
        nanos: opt_int(&v[8]),
        millis: int(&v[9]),
    })
}

fn utc_record(value: &Value) -> Option<UtcRecord> {
    let v = value.as_array()?;
    assert_eq!(v.len(), 5, "DateTime<Utc> row {value}");
    Some(UtcRecord {
        timestamp: int(&v[0]),
        subsec_nanos: small(&v[1]),
        nanos: opt_int(&v[2]),
        millis: int(&v[3]),
        normalized_year: small(&v[4]),
    })
}

/// chrono's results for one input, one entry per parser.
#[derive(Debug, Clone)]
struct Row(Vec<Value>);

impl Row {
    fn rejected_by_all() -> Self {
        Row(vec![Value::Null; ROW_LEN])
    }

    fn fixed(&self, parser: usize) -> Option<FixedRecord> {
        assert!(parser < FIRST_NAIVE_FORMAT);
        fixed_record(&self.0[parser])
    }

    fn naive(&self, format_index: usize) -> Option<NaiveRecord> {
        naive_record(&self.0[FIRST_NAIVE_FORMAT + format_index])
    }

    fn utc(&self) -> Option<UtcRecord> {
        utc_record(&self.0[UTC_FROM_STR])
    }
}

struct Oracle {
    corpus_len: usize,
    corpus_digest: String,
    accepted: HashMap<String, Row>,
    extras: HashMap<String, Row>,
    formats: HashMap<(String, String), (Option<FixedRecord>, Option<NaiveRecord>)>,
    leap: Value,
}

impl Oracle {
    /// chrono's row for a corpus input (all `null` when chrono refused it with
    /// every parser).
    fn corpus_row(&self, input: &str) -> Row {
        self.accepted
            .get(input)
            .cloned()
            .unwrap_or_else(Row::rejected_by_all)
    }

    /// chrono's row for a targeted input; it must be recorded.
    fn row(&self, input: &str) -> &Row {
        self.extras
            .get(input)
            .or_else(|| self.accepted.get(input))
            .unwrap_or_else(|| panic!("no chrono oracle row recorded for {input:?}"))
    }

    fn with_format(&self, input: &str, fmt: &str) -> (Option<FixedRecord>, Option<NaiveRecord>) {
        *self
            .formats
            .get(&(input.to_string(), fmt.to_string()))
            .unwrap_or_else(|| panic!("no chrono oracle entry for {input:?} with {fmt:?}"))
    }
}

fn oracle() -> &'static Oracle {
    static ORACLE: OnceLock<Oracle> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let mut meta = None;
        let mut accepted = HashMap::new();
        let mut extras = HashMap::new();
        let mut formats = HashMap::new();
        let mut leap = None;
        for line in ORACLE_JSONL.lines().filter(|line| !line.trim().is_empty()) {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("bad oracle line {line:?}: {error}"));
            let kind = value["k"].as_str().expect("oracle line kind");
            match kind {
                "meta" => meta = Some(value),
                "c" | "x" => {
                    let input = value["i"].as_str().expect("oracle input").to_string();
                    let row = Row(value["r"].as_array().expect("oracle row").clone());
                    assert_eq!(row.0.len(), ROW_LEN, "row length for {input:?}");
                    let map = if kind == "c" {
                        &mut accepted
                    } else {
                        &mut extras
                    };
                    assert!(
                        map.insert(input.clone(), row).is_none(),
                        "duplicate oracle row for {input:?}"
                    );
                }
                "f" => {
                    let input = value["i"].as_str().expect("oracle input").to_string();
                    let fmt = value["f"].as_str().expect("oracle format").to_string();
                    let entry = (fixed_record(&value["fixed"]), naive_record(&value["naive"]));
                    assert!(
                        formats
                            .insert((input.clone(), fmt.clone()), entry)
                            .is_none(),
                        "duplicate oracle entry for {input:?} with {fmt:?}"
                    );
                }
                "leap" => leap = Some(value),
                other => panic!("unknown oracle line kind {other:?}"),
            }
        }
        let meta = meta.expect("oracle meta line");
        let offset_formats: Vec<&str> = meta["offset_formats"]
            .as_array()
            .expect("offset formats")
            .iter()
            .map(|fmt| fmt.as_str().expect("format"))
            .collect();
        let naive_formats: Vec<&str> = meta["naive_formats"]
            .as_array()
            .expect("naive formats")
            .iter()
            .map(|fmt| fmt.as_str().expect("format"))
            .collect();
        assert_eq!(offset_formats, OFFSET_FORMATS, "oracle offset formats");
        assert_eq!(naive_formats, NAIVE_FORMATS, "oracle naive formats");
        // An input recorded both in the corpus and as an extra must agree.
        for (input, row) in &extras {
            if let Some(corpus_row) = accepted.get(input) {
                assert_eq!(corpus_row.0, row.0, "oracle rows disagree for {input:?}");
            }
        }
        Oracle {
            corpus_len: usize::try_from(int(&meta["len"])).expect("corpus length"),
            corpus_digest: meta["fnv"].as_str().expect("corpus digest").to_string(),
            accepted,
            extras,
            formats,
            leap: leap.expect("oracle leap line"),
        }
    })
}

fn assert_fixed_parity(
    what: &str,
    input: &str,
    ours: Result<ChronoParsedDateTime, TimestampError>,
    theirs: Option<FixedRecord>,
) -> bool {
    match (ours, theirs) {
        (Ok(o), Some(t)) => {
            assert_eq!(
                o.unix_timestamp_nanos_opt(),
                t.nanos,
                "{what}: timestamp_nanos_opt mismatch for {input:?}"
            );
            assert_eq!(
                (
                    o.unix_timestamp(),
                    o.nanosecond(),
                    o.offset_seconds(),
                    o.unix_timestamp_millis()
                ),
                (t.timestamp, t.subsec_nanos, t.offset_seconds, t.millis),
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
                t.local,
                "{what}: local field mismatch for {input:?}"
            );
            assert_utc_conversion(what, input, &o, t.nanos, t.millis);
            true
        }
        (Err(_), None) => false,
        (Ok(o), None) => panic!("{what}: time_compat accepted {input:?} as {o:?}; chrono refused"),
        (Err(e), Some(t)) => panic!("{what}: chrono accepted {input:?} as {t:?}; time_compat: {e}"),
    }
}

fn assert_naive_parity(
    what: &str,
    input: &str,
    ours: Result<ChronoParsedDateTime, TimestampError>,
    theirs: Option<NaiveRecord>,
) -> bool {
    match (ours, theirs) {
        (Ok(o), Some(t)) => {
            assert_eq!(o.offset_seconds(), 0, "{what}: naive offset for {input:?}");
            assert_eq!(
                (
                    o.unix_timestamp(),
                    o.nanosecond(),
                    (
                        o.year(),
                        u32::from(o.month()),
                        u32::from(o.day()),
                        u32::from(o.hour()),
                        u32::from(o.minute()),
                        u32::from(o.second()),
                    ),
                ),
                (t.timestamp, t.nanosecond, t.fields),
                "{what}: naive mismatch for {input:?}"
            );
            assert_utc_conversion(what, input, &o, t.nanos, t.millis);
            true
        }
        (Err(_), None) => false,
        (Ok(o), None) => panic!("{what}: time_compat accepted {input:?} as {o:?}; chrono refused"),
        (Err(e), Some(t)) => panic!("{what}: chrono accepted {input:?} as {t:?}; time_compat: {e}"),
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

/// The oracle rows were recorded from exactly this corpus.
#[test]
fn chrono_oracle_matches_the_mutation_corpus() {
    let corpus = corpus();
    let oracle = oracle();
    assert_eq!(corpus.len(), oracle.corpus_len, "corpus size changed");
    assert_eq!(
        corpus_digest(&corpus),
        oracle.corpus_digest,
        "corpus contents changed; re-record the chrono oracle"
    );
    for input in oracle.accepted.keys() {
        assert!(
            corpus.binary_search(input).is_ok(),
            "oracle row {input:?} is not a corpus input"
        );
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
    let oracle = oracle();

    let mut accepted = [0usize; 3];
    let mut accepted_formats = vec![0usize; OFFSET_FORMATS.len() + NAIVE_FORMATS.len()];
    for input in &corpus {
        let input = input.as_str();
        let row = oracle.corpus_row(input);
        accepted[0] += usize::from(assert_fixed_parity(
            "rfc3339",
            input,
            parse_rfc3339_chrono(input),
            row.fixed(RFC3339),
        ));
        accepted[1] += usize::from(assert_fixed_parity(
            "rfc3339-relaxed",
            input,
            parse_rfc3339_relaxed_chrono(input),
            row.fixed(RFC3339_RELAXED),
        ));
        accepted[2] += usize::from(assert_fixed_parity(
            "rfc2822",
            input,
            parse_rfc2822_chrono(input),
            row.fixed(RFC2822),
        ));
        for (i, fmt) in OFFSET_FORMATS.iter().enumerate() {
            accepted_formats[i] += usize::from(assert_fixed_parity(
                fmt,
                input,
                parse_from_str_chrono(input, fmt),
                row.fixed(FIRST_OFFSET_FORMAT + i),
            ));
        }
        for (i, fmt) in NAIVE_FORMATS.iter().enumerate() {
            accepted_formats[OFFSET_FORMATS.len() + i] += usize::from(assert_naive_parity(
                fmt,
                input,
                parse_naive_from_str_chrono(input, fmt),
                row.naive(i),
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
    let oracle = oracle();
    // Leap second at any minute, kept as second 59 + 1e9 nanoseconds.
    let leap = parse_rfc3339_chrono("2026-11-26T12:30:60.25+01:00").expect("leap second");
    assert!(leap.is_leap_second());
    assert_eq!(leap.second(), 59);
    assert_eq!(leap.nanosecond(), 1_250_000_000);
    let chrono_leap = oracle
        .row("2026-11-26T12:30:60.25+01:00")
        .fixed(RFC3339)
        .expect("chrono accepts the leap second");
    assert_eq!(leap.unix_timestamp(), chrono_leap.timestamp);
    assert_eq!(leap.unix_timestamp_millis(), chrono_leap.millis);
    // Normalized to the next-second instant (owner decision, see below).
    assert_eq!(
        leap.to_utc_timestamp().map(|ts| ts.to_rfc3339_z()),
        Ok("2026-11-26T11:31:00.250Z".to_string())
    );

    // Unicode minus sign in the offset.
    let minus = parse_rfc3339_chrono("2026-11-26T10:20:30\u{2212}05:30").expect("U+2212 offset");
    assert_eq!(minus.offset_seconds(), -(5 * 3_600 + 30 * 60));
    assert_fixed_parity(
        "rfc3339",
        "2026-11-26T10:20:30\u{2212}05:30",
        Ok(minus),
        oracle
            .row("2026-11-26T10:20:30\u{2212}05:30")
            .fixed(RFC3339),
    );

    // Signed or expanded years are refused by the strict parser, as chrono does.
    for input in [
        "+2026-11-26T10:20:30Z",
        "-2026-11-26T10:20:30Z",
        "12026-11-26T10:20:30Z",
        "+012026-11-26T10:20:30Z",
    ] {
        assert!(parse_rfc3339_chrono(input).is_err(), "{input:?}");
        assert!(oracle.row(input).fixed(RFC3339).is_none(), "{input:?}");
    }

    // The existing strict `parse_rfc3339` is unchanged: it still differs on
    // exactly these inputs, which is why parse sites must use the chrono port.
    assert!(oracle.row("2026-11-26T12:30:60Z").fixed(RFC3339).is_some());
    assert!(ferrum_edge::time_compat::parse_rfc3339("2026-11-26T12:30:60Z").is_err());
}

#[test]
fn http_date_forms_used_by_response_caching_and_hmac_auth_follow_chrono() {
    let oracle = oracle();
    let imf = parse_rfc2822_chrono("Sun, 06 Nov 1994 08:49:37 GMT").expect("IMF-fixdate");
    assert_eq!(imf.unix_timestamp(), 784_111_777);
    assert_fixed_parity(
        "rfc2822",
        "Sun, 06 Nov 1994 08:49:37 GMT",
        Ok(imf),
        oracle.row("Sun, 06 Nov 1994 08:49:37 GMT").fixed(RFC2822),
    );
    let rfc850_fmt = "%A, %d-%b-%y %H:%M:%S GMT";
    let rfc850 =
        parse_naive_from_str_chrono("Sunday, 06-Nov-94 08:49:37 GMT", rfc850_fmt).expect("RFC 850");
    assert_eq!(rfc850.unix_timestamp(), 784_111_777);
    assert_naive_parity(
        rfc850_fmt,
        "Sunday, 06-Nov-94 08:49:37 GMT",
        Ok(rfc850),
        oracle
            .with_format("Sunday, 06-Nov-94 08:49:37 GMT", rfc850_fmt)
            .1,
    );
    let asctime_fmt = "%a %b %e %H:%M:%S %Y";
    let asctime =
        parse_naive_from_str_chrono("Sun Nov  6 08:49:37 1994", asctime_fmt).expect("asctime");
    assert_eq!(asctime.unix_timestamp(), 784_111_777);
    assert_naive_parity(
        asctime_fmt,
        "Sun Nov  6 08:49:37 1994",
        Ok(asctime),
        oracle
            .with_format("Sun Nov  6 08:49:37 1994", asctime_fmt)
            .1,
    );

    // A weekday that contradicts the date is refused by both.
    assert!(parse_rfc2822_chrono("Mon, 06 Nov 1994 08:49:37 GMT").is_err());
    assert!(
        oracle
            .row("Mon, 06 Nov 1994 08:49:37 GMT")
            .fixed(RFC2822)
            .is_none()
    );

    // Unsupported specifiers are refused rather than parsed differently.
    assert_eq!(
        parse_naive_from_str_chrono("1994", "%G"),
        Err(TimestampError::InvalidFormat)
    );
    assert!(oracle.with_format("1994", "%G").1.is_none());
}

/// Branches the mutation corpus could otherwise leave untested in both
/// directions: chrono's UTC range check after the offset, a naive parse that
/// ignores an out-of-range offset, `%Y`/`%y` agreement, and padded
/// non-numeric specifiers.
#[test]
fn boundary_and_specifier_cases_follow_chrono() {
    let oracle = oracle();
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
                let row = oracle.row(input);
                assert_fixed_parity(
                    "rfc2822",
                    input,
                    parse_rfc2822_chrono(input),
                    row.fixed(RFC2822),
                );
                assert_fixed_parity(
                    "rfc3339-relaxed",
                    input,
                    parse_rfc3339_relaxed_chrono(input),
                    row.fixed(RFC3339_RELAXED),
                );
            }
            Some(fmt) => {
                assert_fixed_parity(
                    fmt,
                    input,
                    parse_from_str_chrono(input, fmt),
                    oracle.with_format(input, fmt).0,
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
            oracle.with_format(input, fmt).1,
        );
    }
    assert!(parse_naive_from_str_chrono("2026-11-26T10:20:30+9959", "%Y-%m-%dT%H:%M:%S%z").is_ok());
    assert!(parse_from_str_chrono("2026-11-26T10:20:30+9959", "%Y-%m-%dT%H:%M:%S%z").is_err());
    assert!(parse_naive_from_str_chrono("2026/26 11 26 10:20", "%Y/%y %m %d %H:%M").is_ok());
    assert!(parse_naive_from_str_chrono("2026/27 11 26 10:20", "%Y/%y %m %d %H:%M").is_err());
    assert!(parse_naive_from_str_chrono("2026-11-26 10:20.5", "%Y-%m-%d %H:%M%.f").is_err());
    assert!(parse_naive_from_str_chrono("2026-11-26 10:20", "%Y-%m-%d %H:%M%.f").is_ok());
    assert_naive_parity(
        "%Y-%m-%d %H:%M%.f",
        "2026-11-26 10:20",
        parse_naive_from_str_chrono("2026-11-26 10:20", "%Y-%m-%d %H:%M%.f"),
        oracle
            .with_format("2026-11-26 10:20", "%Y-%m-%d %H:%M%.f")
            .1,
    );
}

/// #7419 owner decision (option B): a parsed leap second is stored as the
/// next-second instant chrono's `timestamp_nanos_opt()` reports. Millis and
/// nanos equal chrono's; the formatting, whole-second and in-window ordering
/// differences below are known and accepted, and pinned here so they stay
/// deliberate.
#[test]
fn leap_second_normalization_matches_chrono_nanos_and_documents_differences() {
    let oracle = oracle();
    let input = "1999-12-31T23:59:60.5Z";
    let chrono_leap = oracle
        .row(input)
        .utc()
        .expect("chrono accepts the leap second");
    let stored = parse_rfc3339_chrono(input)
        .and_then(|parsed| parsed.to_utc_timestamp())
        .expect("leap second normalizes");

    // Equal to chrono.
    assert_eq!(
        stored.unix_timestamp_nanos(),
        i128::from(chrono_leap.nanos.expect("in chrono's nanosecond range"))
    );
    assert_eq!(stored.unix_timestamp_millis(), chrono_leap.millis);
    let as_stored = |input: &str| {
        let chrono = oracle.row(input).utc().expect("chrono accepts the input");
        UtcTimestamp::from_unix_timestamp_nanos(chrono.timestamp, chrono.subsec_nanos).unwrap()
    };
    let ordering = |name: &str| match oracle.leap[name].as_str() {
        Some("Less") => std::cmp::Ordering::Less,
        Some("Equal") => std::cmp::Ordering::Equal,
        Some("Greater") => std::cmp::Ordering::Greater,
        other => panic!("bad recorded ordering {name}: {other:?}"),
    };
    assert_eq!(
        stored.cmp(&as_stored("1999-12-31T23:59:59.999999999Z")),
        ordering("cmp_before")
    );
    assert_eq!(
        stored.cmp(&as_stored("2000-01-01T00:00:01Z")),
        ordering("cmp_after")
    );

    // Known, accepted differences.
    assert_eq!(
        oracle.leap["rfc3339"].as_str(),
        Some("1999-12-31T23:59:60.500+00:00")
    );
    assert_eq!(stored.to_rfc3339(), "2000-01-01T00:00:00.500+00:00");
    assert_eq!(stored.unix_timestamp(), chrono_leap.timestamp + 1);
    assert_eq!(ordering("cmp_inside"), std::cmp::Ordering::Less);
    assert_eq!(
        stored.cmp(&as_stored("2000-01-01T00:00:00.25Z")),
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
    let oracle = oracle();
    let strict = "9999-12-31T23:30:00-01:00";
    let parsed = parse_rfc3339_chrono(strict).expect("strict RFC 3339 accepts");
    assert_fixed_parity(
        "rfc3339",
        strict,
        Ok(parsed),
        oracle.row(strict).fixed(RFC3339),
    );
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    let rfc2822 = "Mon, 26 Nov 12345 10:20:30 GMT";
    let parsed = parse_rfc2822_chrono(rfc2822).expect("RFC 2822 accepts");
    assert_fixed_parity(
        "rfc2822",
        rfc2822,
        Ok(parsed),
        oracle.row(rfc2822).fixed(RFC2822),
    );
    assert_eq!(parsed.year(), 12345);
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    let relaxed = "+12345-01-01T00:00:00Z";
    let parsed = parse_rfc3339_relaxed_chrono(relaxed).expect("relaxed RFC 3339 accepts");
    assert_fixed_parity(
        "rfc3339-relaxed",
        relaxed,
        Ok(parsed),
        oracle.row(relaxed).fixed(RFC3339_RELAXED),
    );
    assert_eq!(parsed.to_utc_timestamp(), Err(TimestampError::OutOfRange));

    // The nearest in-range neighbours still convert.
    assert!(
        parse_rfc3339_chrono("9999-12-31T23:30:00+00:00")
            .and_then(|parsed| parsed.to_utc_timestamp())
            .is_ok()
    );
}

/// `UtcTimestamp`'s `FromStr` and serde `Deserialize` accept exactly what
/// chrono's `DateTime<Utc>` does (both use chrono's relaxed RFC 3339 parser).
/// Accepted values carry chrono's instant (a leap second normalized to the
/// next-second linear instant); the only refusals chrono does not make are
/// instants outside `UtcTimestamp`'s `-9999..=9999` range (issue #7419 owner
/// decisions).
#[test]
fn from_str_and_deserialize_match_chrono_on_the_mutation_corpus() {
    let oracle = oracle();
    let mut accepted = 0usize;
    let mut out_of_range = 0usize;
    for input in corpus() {
        let input = input.as_str();
        let theirs = oracle.corpus_row(input).utc();
        let ours_str = input.parse::<UtcTimestamp>();
        let ours_json = serde_json::from_value::<UtcTimestamp>(Value::from(input));
        assert_eq!(
            ours_str.as_ref().ok(),
            ours_json.as_ref().ok(),
            "UtcTimestamp FromStr and serde disagree on {input:?}"
        );
        match (ours_str, theirs) {
            (Ok(ours), Some(theirs)) => {
                accepted += 1;
                assert_eq!(
                    ours.unix_timestamp_millis(),
                    theirs.millis,
                    "millis for {input:?}"
                );
                if let Some(nanos) = theirs.nanos {
                    assert_eq!(
                        ours.unix_timestamp_nanos(),
                        i128::from(nanos),
                        "nanos for {input:?}"
                    );
                }
            }
            (Err(error), Some(theirs)) => {
                out_of_range += 1;
                assert_eq!(error, TimestampError::OutOfRange, "{input:?} -> {theirs:?}");
                // Independently of time_compat: chrono's instant, with a leap
                // second moved to the next second (owner option B), lies
                // outside -9999..=9999 (i32::MAX past chrono's own maximum).
                let year = theirs.normalized_year;
                assert!(
                    !(-9999..=9999).contains(&year),
                    "{input:?} refused although its UTC year {year} is in range"
                );
            }
            (Ok(ours), None) => {
                panic!("UtcTimestamp accepted {input:?} as {ours:?}; chrono refused")
            }
            (Err(_), None) => {}
        }
    }
    assert!(accepted > 200, "only {accepted} corpus inputs accepted");
    assert!(
        out_of_range > 0,
        "the corpus must exercise the out-of-range refusal"
    );

    // The relaxed forms chrono's serde accepts.
    for input in [
        "2026-1-2T3:4:5Z",
        " 2026 - 11 - 26T10 : 20 : 30.5 Z ",
        "2026-11-26T10:20:30 UTC",
        "2026-11-26T10:20:30+0530",
        "2026-11-26T10:20:30 +05 30",
    ] {
        let ours: UtcTimestamp = serde_json::from_value(Value::from(input))
            .unwrap_or_else(|error| panic!("{input:?}: {error}"));
        let theirs = oracle.row(input).utc().expect("chrono accepts the input");
        assert_eq!(
            ours.unix_timestamp_nanos(),
            i128::from(theirs.nanos.expect("in chrono's nanosecond range"))
        );
    }
    // A leap second deserializes to the next-second instant.
    let leap: UtcTimestamp = serde_json::from_value(Value::from("1999-12-31T23:59:60.5Z")).unwrap();
    assert_eq!(leap.to_rfc3339_z(), "2000-01-01T00:00:00.500Z");
    // Out-of-range years chrono's serde accepts are refused.
    assert!(oracle.row("+12345-01-01T00:00:00Z").utc().is_some());
    assert!(serde_json::from_value::<UtcTimestamp>(Value::from("+12345-01-01T00:00:00Z")).is_err());
}
