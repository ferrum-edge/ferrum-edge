//! Production Dockerfile base images must be digest-pinned (issue #4444).

use std::collections::HashMap;

const PRODUCTION_DOCKERFILES: &[(&str, &str)] = &[
    ("Dockerfile", include_str!("../../../Dockerfile")),
    (
        "Dockerfile.release",
        include_str!("../../../Dockerfile.release"),
    ),
    ("Dockerfile.test", include_str!("../../../Dockerfile.test")),
    // The eBPF tools layer builds a published `-ebpf-tools` image, so it is a
    // production image and belongs in this inventory.
    (
        "Dockerfile.ebpf-tools-layer",
        include_str!("../../../Dockerfile.ebpf-tools-layer"),
    ),
    (
        "Dockerfile.iproute2-layer",
        include_str!("../../../Dockerfile.iproute2-layer"),
    ),
];

const FLOATING_RUST_TAGS: &[&str] = &["latest", "stable", "nightly", "beta"];

/// A Dockerfile comment is a WHOLE line beginning with `#`; the parser has no
/// inline-comment form, so everything after a `#` on an `ARG` or `FROM` line is
/// part of that instruction's arguments. Treating `#` as an inline comment here
/// would let this test pass over a Dockerfile the builder cannot parse, which is
/// exactly the failure this gate exists to prevent.
fn instruction_line(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        ""
    } else {
        trimmed
    }
}

fn instruction_keyword(instruction: &str) -> &str {
    instruction.split_whitespace().next().unwrap_or_default()
}

fn is_arg_name(name: &str) -> bool {
    let word = |b: u8| b == b'_' || b.is_ascii_alphanumeric();
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(first) if word(first) && !first.is_ascii_digit() => bytes.all(word),
        _ => false,
    }
}

/// `ARG <NAME>[=<value>]` and nothing else. `None` when the line is not an
/// `ARG` instruction; `Err` when it is one this gate cannot read completely,
/// such as a pinned default followed by a note.
fn parse_arg_instruction(line: &str) -> Option<Result<(String, Option<String>), String>> {
    let trimmed = instruction_line(line);
    if !instruction_keyword(trimmed).eq_ignore_ascii_case("ARG") {
        return None;
    }
    let unsupported = format!("unsupported `ARG` instruction `{trimmed}`");
    let tokens: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
    let [declaration] = tokens.as_slice() else {
        return Some(Err(unsupported));
    };
    let (name, value) = match declaration.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (*declaration, None),
    };
    if !is_arg_name(name) || value.is_some_and(str::is_empty) {
        return Some(Err(unsupported));
    }
    Some(Ok((name.to_string(), value.map(str::to_string))))
}

/// `FROM [--flag=value ...] <image> [AS <alias>]` and nothing else. `None` when
/// the line is not a `FROM` instruction; `Err` when it is one this gate cannot
/// read completely, such as a pinned reference followed by a note.
fn parse_from_instruction(line: &str) -> Option<Result<String, String>> {
    let trimmed = instruction_line(line);
    if !instruction_keyword(trimmed).eq_ignore_ascii_case("FROM") {
        return None;
    }
    let mut tokens = trimmed
        .split_whitespace()
        .skip(1)
        .skip_while(|token| token.starts_with("--"));
    let image = tokens.next();
    let rest: Vec<&str> = tokens.collect();
    let complete = match rest.as_slice() {
        [] => true,
        [keyword, _alias] => keyword.eq_ignore_ascii_case("AS"),
        _ => false,
    };
    match image {
        Some(image) if complete => Some(Ok(image.to_string())),
        _ => Some(Err(format!("unsupported `FROM` instruction `{trimmed}`"))),
    }
}

fn is_local_stage_reference(image: &str) -> bool {
    !image.contains('/') && !image.contains('@') && !image.contains(':') && !image.starts_with("${")
}

fn resolve_image_reference(image: &str, arg_defaults: &HashMap<String, String>) -> String {
    if let Some(var) = image
        .strip_prefix("${")
        .and_then(|name| name.strip_suffix('}'))
    {
        return arg_defaults
            .get(var)
            .cloned()
            .unwrap_or_else(|| image.to_string());
    }
    image.to_string()
}

/// The whole reference must end in `@sha256:<64 lowercase hex>`; containing the
/// marker somewhere is not enough.
fn is_digest_pinned(reference: &str) -> bool {
    let Some((image, digest)) = reference.rsplit_once("@sha256:") else {
        return false;
    };
    let hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    !image.is_empty()
        && !image.contains(char::is_whitespace)
        && digest.len() == 64
        && digest.bytes().all(hex)
}

fn rust_channel_violation(
    file: &str,
    line_no: usize,
    line: &str,
    resolved: &str,
) -> Option<String> {
    let repo = resolved.split('@').next().unwrap_or(resolved);
    let is_rust = repo == "rust"
        || repo.ends_with("/rust")
        || repo.ends_with("/library/rust")
        || repo == "docker.io/library/rust";
    if !is_rust {
        return None;
    }

    // `repo:tag@sha256:...` is the pinned form this repository already uses for
    // `IPROUTE2_BASE`: the digest decides which bytes are pulled and the tag is
    // documentation, so a floating tag is only a finding when NO digest pins it.
    if is_digest_pinned(resolved) {
        return None;
    }

    let tag = resolved
        .rsplit_once(':')
        .map(|(_, tag)| tag)
        .unwrap_or("latest");

    if !FLOATING_RUST_TAGS.contains(&tag) {
        return None;
    }
    Some(format!(
        "{file}:{line_no}: unapproved floating Rust channel `{tag}` in `{line}`; pin the \
         manifest-list digest as `rust:<tag>@sha256:<digest>`"
    ))
}

/// Every pin violation in one Dockerfile. An instruction this gate cannot read
/// completely is itself a violation, so it can never drop out of the scan.
fn dockerfile_pin_violations(file: &str, dockerfile: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let mut arg_defaults = HashMap::new();
    for (idx, line) in dockerfile.lines().enumerate() {
        match parse_arg_instruction(line) {
            Some(Ok((name, Some(value)))) => {
                arg_defaults.insert(name, value);
            }
            Some(Err(error)) => violations.push(format!("{file}:{}: {error}", idx + 1)),
            Some(Ok((_, None))) | None => {}
        }
    }
    for (idx, line) in dockerfile.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        let image = match parse_from_instruction(line) {
            Some(Ok(image)) => image,
            Some(Err(error)) => {
                violations.push(format!("{file}:{line_no}: {error}"));
                continue;
            }
            None => continue,
        };
        if image == "scratch" || is_local_stage_reference(&image) {
            continue;
        }

        let resolved = resolve_image_reference(&image, &arg_defaults);
        if !is_digest_pinned(&resolved) {
            violations.push(format!(
                "{file}:{line_no}: production Dockerfile `FROM` must pin external bases by \
                 `@sha256:` digest (allow `scratch` or a local stage alias); got `{trimmed}`"
            ));
        }
        if let Some(violation) = rust_channel_violation(file, line_no, trimmed, &resolved) {
            violations.push(violation);
        }
    }
    violations
}

#[test]
fn production_dockerfiles_pin_external_bases_by_digest() {
    for (file, dockerfile) in PRODUCTION_DOCKERFILES {
        let violations = dockerfile_pin_violations(file, dockerfile);
        assert!(violations.is_empty(), "{}", violations.join("\n"));
    }
}

// The runtime repository is synthetic on purpose: a literal distroless pin here
// would be read as a consumer by the repository-wide distroless consistency gate
// in `.github/scripts/verify_ci_runtime_cache.py`.
const PINNED_FIXTURE: &str = "\
ARG RUNTIME_BASE=registry.example/runtime/cc:nonroot@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ARG IPROUTE2_VERSION=6.15.0-1
# Digest resolved YYYY-MM-DD; the tag is kept for readability, the digest is authoritative.
FROM debian:13-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb AS data-dir
FROM ${RUNTIME_BASE} AS runtime
";

#[test]
fn pinned_fixture_has_no_violations() {
    let violations = dockerfile_pin_violations("fixture", PINNED_FIXTURE);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

/// Issue #6382: a note appended after a `FROM` or image `ARG` instruction must
/// fail as an unsupported instruction, not be read as its first token.
#[test]
fn trailing_text_after_a_pin_instruction_is_rejected() {
    let cases = [
        (" AS data-dir\n", " AS data-dir # resolved today\n", 4),
        (" AS runtime\n", " AS runtime extra\n", 5),
        (
            "aaaa\nARG IPROUTE2",
            "aaaa # resolved today\nARG IPROUTE2",
            1,
        ),
        ("6.15.0-1\n", "6.15.0-1 # note\n", 2),
    ];
    for (original, replacement, line_no) in cases {
        let tailed = PINNED_FIXTURE.replacen(original, replacement, 1);
        assert!(
            tailed != PINNED_FIXTURE,
            "fixture replacement `{original}` must apply"
        );
        let violations = dockerfile_pin_violations("fixture", &tailed);
        let prefix = format!("fixture:{line_no}: unsupported");
        assert!(
            violations.iter().any(|v| v.starts_with(&prefix)),
            "trailing text on line {line_no} must be rejected; got {violations:?}"
        );
    }
}

#[test]
fn digest_must_terminate_the_reference() {
    let digest = "b".repeat(64);
    let truncated = PINNED_FIXTURE.replacen(&digest, &digest[1..], 1);
    let violations = dockerfile_pin_violations("fixture", &truncated);
    let prefix = "fixture:4: production Dockerfile";
    assert!(
        violations.iter().any(|v| v.starts_with(prefix)),
        "a short digest must not count as pinned; got {violations:?}"
    );
}
