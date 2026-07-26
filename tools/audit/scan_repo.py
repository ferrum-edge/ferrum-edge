#!/usr/bin/env python3
"""Static launch-readiness candidate scanner.

This scanner is deliberately a *candidate generator*, not an automatic bug oracle.
It records exact paths, lines, function context, risk class, and nearby source so a
reviewer can validate each candidate before publication.  Generated output never
contains credentials and is safe to keep on the isolated audit branch.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

TEXT_EXTENSIONS = {
    ".rs", ".py", ".sh", ".bash", ".yml", ".yaml", ".toml", ".json",
    ".md", ".proto", ".sql", ".dockerfile", ".conf", ".ini", ".env",
}
TEXT_NAMES = {
    "Dockerfile", "Dockerfile.release", "Dockerfile.test", "Makefile",
    "Justfile", "build.rs", "ferrum.conf", "Cross.toml", "deny.toml",
}
SKIP_DIRS = {
    ".git", "target", "node_modules", ".cache", ".venv", "venv", "dist",
    "build", "generated", ".idea", ".vscode",
}
TEST_PATH_PARTS = {
    "tests", "test", "benches", "benchmarks", "fixtures", "examples",
}
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_MATCHES_PER_RULE_PER_FILE = 80


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: str
    message: str
    severity: str = "medium"
    confidence: str = "medium"
    extensions: tuple[str, ...] = (".rs",)
    flags: int = 0
    prod_only: bool = False
    context_before: int = 5
    context_after: int = 8


@dataclass
class Candidate:
    id: str
    fingerprint: str
    score: int
    rule: str
    category: str
    severity_hint: str
    confidence_hint: str
    path: str
    line: int
    column: int
    function: str
    in_async: bool
    in_hot_scope: bool
    in_loop_scope: bool
    test_code: bool
    excerpt: str
    message: str
    context_start: int
    context_end: int
    context: list[str]


RULES: tuple[Rule, ...] = (
    Rule("rust-prod-unwrap", "correctness", r"\.(?:unwrap|expect)\s*\(",
         "Reachable unwrap/expect can terminate the process instead of returning a controlled error.",
         "high", "medium", prod_only=True),
    Rule("rust-panic-macro", "correctness", r"\b(?:panic|todo|unimplemented)\s*!\s*\(",
         "Production panic/todo/unimplemented path can crash or make an advertised branch unusable.",
         "high", "high", prod_only=True),
    Rule("rust-unreachable-macro", "correctness", r"\bunreachable\s*!\s*\(",
         "An assumed-impossible branch may be reachable after configuration or protocol evolution.",
         "high", "medium", prod_only=True),
    Rule("rust-unsafe-block", "memory-safety", r"\bunsafe\s*\{",
         "Unsafe code needs explicit invariant, bounds, lifetime, and concurrency review.",
         "high", "medium", prod_only=True),
    Rule("rust-unchecked-operation", "memory-safety",
         r"\b(?:get_unchecked|from_utf8_unchecked|transmute|assume_init|set_len)\b",
         "Unchecked memory/string operation can violate Rust safety invariants if inputs drift.",
         "high", "high", prod_only=True),
    Rule("rust-unbounded-channel", "resource-exhaustion", r"\bunbounded_channel\s*\(",
         "Unbounded channel permits producer traffic to retain memory without backpressure.",
         "high", "high", prod_only=True),
    Rule("rust-std-mutex", "concurrency", r"\bstd::sync::(?:Mutex|RwLock)\b",
         "Blocking mutex/RwLock may stall an async executor or request hot path.",
         "high", "medium", prod_only=True),
    Rule("rust-blocking-sleep", "concurrency", r"\b(?:std::thread::sleep|thread::sleep)\s*\(",
         "Blocking sleep can monopolize an executor worker when called from async code.",
         "high", "high", prod_only=True),
    Rule("rust-blocking-fs", "concurrency",
         r"\bstd::fs::(?:read|read_to_string|write|copy|rename|remove_file|remove_dir_all|metadata|canonicalize|create_dir_all|read_dir)\s*\(",
         "Synchronous filesystem operation may block an async/runtime worker.",
         "medium", "medium", prod_only=True),
    Rule("rust-blocking-command", "concurrency", r"\bstd::process::Command\b|\bCommand::new\s*\(",
         "Child-process launch is blocking and needs timeout, output cap, and argument provenance review.",
         "high", "medium", prod_only=True),
    Rule("rust-detached-spawn", "lifecycle", r"(?<![=\w])tokio::spawn\s*\(",
         "Detached task may outlive reload/shutdown ownership and hide failures.",
         "medium", "medium", prod_only=True),
    Rule("rust-spawn-blocking", "resource-exhaustion", r"\bspawn_blocking\s*\(",
         "spawn_blocking work needs explicit admission control and shutdown ownership.",
         "medium", "medium", prod_only=True),
    Rule("rust-read-to-end", "resource-exhaustion", r"\bread_to_end\s*\(",
         "Read-to-end can allocate until EOF unless a hard byte limit is enforced upstream.",
         "high", "high", prod_only=True),
    Rule("rust-read-to-string", "resource-exhaustion", r"\bread_to_string\s*\(",
         "Read-to-string can allocate until EOF unless a hard byte limit is enforced upstream.",
         "high", "medium", prod_only=True),
    Rule("rust-body-collect", "resource-exhaustion",
         r"\b(?:to_bytes|collect_body|body\.collect|collect::<\s*Bytes|collect::<\s*Vec)\b",
         "Whole-body/materializing collection needs an independently enforced byte cap.",
         "high", "medium", prod_only=True),
    Rule("rust-variable-capacity", "resource-exhaustion",
         r"(?:Vec|String|BytesMut)::with_capacity\s*\((?!\s*\d+\s*\))",
         "Variable-derived preallocation can amplify attacker-controlled lengths.",
         "medium", "medium", prod_only=True),
    Rule("rust-accept-loop", "availability", r"\.accept\s*\(\s*\)\.await",
         "Listener accept error path needs bounded backoff and shutdown handling to avoid a hot failure loop.",
         "medium", "medium", prod_only=True),
    Rule("rust-network-connect", "availability",
         r"\b(?:TcpStream::connect|UdpSocket::connect|lookup_host|connect_async|Endpoint::from_shared)\b",
         "Network establishment needs connect timeout, cancellation, DNS policy, and address-rotation review.",
         "medium", "medium", prod_only=True),
    Rule("rust-client-builder", "performance", r"\b(?:reqwest::Client::new|Client::builder|HttpConnector::new)\s*\(",
         "Client construction inside a request/plugin method can defeat pooling and repeat TLS/DNS setup.",
         "medium", "medium", prod_only=True),
    Rule("rust-regex-compile", "performance", r"\bRegex(?:Set)?::new\s*\(",
         "Regex compilation should normally occur at config load, not per request/message.",
         "medium", "medium", prod_only=True),
    Rule("rust-json-materialize", "performance",
         r"serde_json::(?:to_vec|to_string|from_slice|from_str)\s*\(",
         "JSON materialization on a hot/body path can add full-size copies and CPU work.",
         "medium", "low", prod_only=True),
    Rule("rust-string-lossy", "correctness", r"String::from_utf8_lossy\s*\(",
         "Lossy UTF-8 conversion can alter signed, routed, filtered, or audited bytes.",
         "medium", "medium", prod_only=True),
    Rule("rust-to-vec", "performance", r"\.(?:to_vec|to_string)\s*\(\s*\)",
         "Owned copy in a hot/body path may duplicate payloads or configuration snapshots.",
         "medium", "low", prod_only=True),
    Rule("rust-full-sort", "performance", r"\.(?:sort|sort_by|sort_by_key|sort_unstable|sort_unstable_by)\s*\(",
         "Full sorting in request/status/eviction paths can turn bounded work into O(n log n).",
         "medium", "medium", prod_only=True),
    Rule("rust-map-full-scan", "performance", r"\.(?:iter|values|keys)\s*\(\s*\)",
         "Full collection scan may be on a request, metric-render, reload, or eviction path.",
         "medium", "low", prod_only=True),
    Rule("rust-map-insert", "resource-exhaustion", r"\.(?:insert|entry)\s*\(",
         "State insertion needs cardinality, byte, TTL, and lifecycle bounds when keys can be traffic-derived.",
         "medium", "low", prod_only=True),
    Rule("rust-let-underscore", "error-handling", r"\blet\s+_\s*=",
         "Discarded return value may hide persistence, cleanup, delivery, or task failures.",
         "medium", "medium", prod_only=True),
    Rule("rust-result-ok", "error-handling", r"\.ok\s*\(\s*\)",
         "Converting Result to Option erases the cause and can silently skip invalid or failed work.",
         "medium", "medium", prod_only=True),
    Rule("rust-filter-map-ok", "error-handling", r"filter_map\s*\([^\n]*\.ok\s*\(\s*\)",
         "filter_map(Result::ok) silently drops malformed or failed entries.",
         "high", "high", prod_only=True),
    Rule("rust-unwrap-or-default", "error-handling", r"\.unwrap_or_default\s*\(",
         "Default-on-error may turn invalid input or failed state retrieval into permissive behavior.",
         "medium", "medium", prod_only=True),
    Rule("rust-unwrap-or-true", "security", r"\.unwrap_or\s*\(\s*true\s*\)",
         "Defaulting a failed/missing decision to true can fail open.",
         "high", "high", prod_only=True),
    Rule("rust-if-let-ok", "error-handling", r"\bif\s+let\s+Ok\s*\(",
         "if-let-Ok without an else can silently ignore an operational or validation failure.",
         "medium", "low", prod_only=True),
    Rule("rust-log-secret", "data-exposure",
         r"(?:trace|debug|info|warn|error)!\s*\([^\n]*(?:token|secret|password|authorization|cookie|api[_-]?key|private[_-]?key)",
         "Logging credential-bearing values can expose secrets through normal diagnostics.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-dangerous-tls", "security",
         r"danger_accept_invalid_(?:certs|hostnames)|NoCertificateVerification|tls_no_verify|insecure_skip_verify",
         "TLS verification bypass must be tightly gated and must not leak into production defaults.",
         "high", "high", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-weak-hash", "security", r"\b(?:md5|sha1|Sha1)\b",
         "Weak hash use needs review for signatures, integrity, cache keys, and credential storage.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-secret-equality", "security",
         r"(?:token|secret|signature|password|api_key|hmac)[^\n]{0,80}(?:==|!=)|(?:==|!=)[^\n]{0,80}(?:token|secret|signature|password|api_key|hmac)",
         "Direct equality on secret material may be timing-sensitive or compare transformed representations.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-jwt-decode", "security", r"\bjsonwebtoken::decode\b|\bdecode::<",
         "JWT validation needs explicit algorithm, issuer, audience, time, key-selection, and replay policy review.",
         "high", "medium", prod_only=True),
    Rule("rust-wildcard-cors", "security",
         r"Access-Control-Allow-Origin|allow_any_origin|HeaderValue::from_static\(\s*\"\*\"",
         "Wildcard cross-origin access can expose management or credentialed endpoints.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-shell-command", "injection", r"Command::new\s*\(\s*\"(?:sh|bash)\"|\.arg\s*\(\s*\"-c\"",
         "Shell execution needs strict non-user-controlled command construction and timeout/output caps.",
         "high", "high", prod_only=True),
    Rule("rust-dynamic-path-join", "filesystem-security",
         r"\.join\s*\([^\n]*(?:tenant|namespace|node|proxy|plugin|consumer|id|name|key)",
         "Dynamic identifier used in a path needs canonical containment, separator, symlink, and collision checks.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-file-write", "durability",
         r"\b(?:tokio::fs|std::fs)::(?:write|rename|copy|remove_file|remove_dir_all|create_dir_all)\b",
         "Filesystem mutation needs atomicity, fsync, ownership, symlink, quota, and crash-recovery review.",
         "medium", "medium", prod_only=True),
    Rule("rust-relaxed-atomic", "concurrency", r"Ordering::Relaxed",
         "Relaxed atomic ordering is unsafe for lifecycle/state publication unless independently synchronized.",
         "medium", "medium", prod_only=True),
    Rule("rust-arc-swap-store", "concurrency", r"\.store\s*\(\s*Arc::new|ArcSwap[^\n]*\.store",
         "Blind ArcSwap store can lose concurrent updates when derived from a stale snapshot.",
         "high", "medium", prod_only=True),
    Rule("rust-narrowing-cast", "correctness", r"\bas\s+(?:u8|u16|u32|i8|i16|i32|usize)\b",
         "Narrowing/platform-dependent cast needs overflow/truncation validation.",
         "medium", "low", prod_only=True),
    Rule("rust-system-time-unwrap", "correctness",
         r"SystemTime::now\s*\(\s*\)[^\n]{0,120}duration_since[^\n]{0,120}\.(?:unwrap|expect)",
         "Wall-clock rollback can panic duration_since-based logic.",
         "high", "high", prod_only=True),
    Rule("rust-user-metric-label", "observability",
         r"(?:label|labels|with_label_values)[^\n]*(?:path|host|url|user|consumer|tenant|namespace|proxy_id|request_id)",
         "Traffic-derived metric labels can create unbounded Prometheus cardinality.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-format-hot", "performance", r"\bformat!\s*\(",
         "format! allocates; verify it is not in a per-request/per-message hot loop.",
         "medium", "low", prod_only=True),
    Rule("rust-serde-default-sensitive", "configuration-security",
         r"#\[serde\([^\]]*default[^\]]*\)\][\s\n]*(?:pub\s+)?(?:allow|enabled|verify|auth|tls|secure|fail_open|enforce)",
         "Security-sensitive serde default can silently change enforcement when a field is omitted.",
         "high", "medium", prod_only=True, flags=re.IGNORECASE),
    Rule("rust-todo-comment", "implementation-gap", r"\b(?:TODO|FIXME|HACK|XXX)\b",
         "Explicit unfinished or workaround marker needs launch-readiness disposition.",
         "medium", "medium", extensions=(".rs", ".py", ".sh", ".yml", ".yaml", ".toml", ".proto", ".sql"),
         flags=re.IGNORECASE, prod_only=True),
    Rule("rust-gap-language", "implementation-gap",
         r"\b(?:not implemented|unsupported|best[- ]effort|fail[-_ ]open|intentionally ignored|silently ignore|deferred|no-op)\b",
         "Documented unsupported/best-effort/fail-open branch may be a pre-launch gap.",
         "medium", "medium", extensions=(".rs", ".py", ".sh", ".yml", ".yaml", ".toml", ".proto", ".sql"),
         flags=re.IGNORECASE, prod_only=True),
    Rule("rust-ignore-test", "test-gap", r"#\[(?:ignore|cfg\([^\]]*(?:test|feature)[^\]]*\))\]",
         "Ignored or narrowly gated test may leave a production branch outside required CI.",
         "medium", "medium", extensions=(".rs",)),
    Rule("yaml-continue-on-error", "ci-integrity", r"continue-on-error\s*:\s*true",
         "Required CI step can fail without failing the workflow.",
         "high", "high", extensions=(".yml", ".yaml")),
    Rule("yaml-unpinned-action", "supply-chain", r"uses\s*:\s*[^\s#]+@(?:main|master|v\d+)\s*$",
         "Action is not pinned to an immutable commit SHA.",
         "high", "high", extensions=(".yml", ".yaml"), flags=re.MULTILINE),
    Rule("yaml-privileged", "container-security", r"privileged\s*:\s*true|hostNetwork\s*:\s*true|hostPID\s*:\s*true",
         "Privileged/host namespace workload materially expands compromise impact.",
         "high", "high", extensions=(".yml", ".yaml"), flags=re.IGNORECASE),
    Rule("yaml-latest-image", "supply-chain", r"image\s*:\s*[^\s]+:(?:latest|main)\b",
         "Mutable container tag prevents reproducible deployment and rollback.",
         "medium", "high", extensions=(".yml", ".yaml"), flags=re.IGNORECASE),
    Rule("yaml-missing-probe-marker", "operations", r"kind\s*:\s*(?:Deployment|DaemonSet|StatefulSet)",
         "Workload should be reviewed for startup/readiness/liveness probes, resource limits, and disruption behavior.",
         "medium", "low", extensions=(".yml", ".yaml"), flags=re.IGNORECASE),
    Rule("shell-error-suppression", "ci-integrity", r"\|\|\s*true\b|set\s+\+e\b|2>/dev/null",
         "Shell failure suppression may hide a required validation, cleanup, or deployment failure.",
         "medium", "medium", extensions=(".sh", ".bash", ".yml", ".yaml")),
    Rule("shell-eval", "injection", r"\beval\b|(?:bash|sh)\s+-c\s+[^\"']*\$",
         "Dynamic shell evaluation can become command injection.",
         "high", "high", extensions=(".sh", ".bash", ".yml", ".yaml")),
    Rule("shell-unverified-download", "supply-chain", r"\bcurl\b|\bwget\b",
         "Downloaded executable/archive needs immutable version, digest/signature verification, timeout, and retry review.",
         "medium", "low", extensions=(".sh", ".bash", ".yml", ".yaml", ".dockerfile")),
    Rule("sql-select-star", "database-performance", r"\bSELECT\s+\*\b",
         "SELECT * couples queries to schema growth and may retrieve unnecessary large columns.",
         "medium", "medium", extensions=(".rs", ".sql"), flags=re.IGNORECASE),
    Rule("proto-unbounded-repeated", "resource-exhaustion", r"\brepeated\s+(?:bytes|string|[A-Za-z_][\w.]*)\s+\w+\s*=",
         "Repeated protobuf field needs message-size and element-count limits at ingress.",
         "medium", "medium", extensions=(".proto",)),
    Rule("proto-bytes-field", "resource-exhaustion", r"\bbytes\s+\w+\s*=",
         "Bytes protobuf field needs explicit decoded-size limits before allocation/use.",
         "medium", "medium", extensions=(".proto",)),
)


FUNCTION_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<async>async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
HOT_NAME_RE = re.compile(
    r"(?:handle|request|response|proxy|dispatch|execute|process|route|lookup|select|accept|recv|send|record|observe|metric|authorize|authenticate|filter|transform|stream|forward|relay|connect)",
    re.IGNORECASE,
)
LOOP_RE = re.compile(r"\b(?:for\s+.+\s+in|while\s+|loop\s*\{)")


def is_test_path(path: Path) -> bool:
    lower_parts = {p.lower() for p in path.parts}
    return bool(lower_parts & TEST_PATH_PARTS) or path.name.endswith("_test.rs")


def should_scan(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.name in TEXT_NAMES:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def clean_excerpt(line: str, limit: int = 260) -> str:
    value = " ".join(line.strip().split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def nearest_function(lines: Sequence[str], line_index: int) -> tuple[str, bool, bool]:
    start = max(0, line_index - 240)
    for idx in range(line_index, start - 1, -1):
        match = FUNCTION_RE.match(lines[idx])
        if match:
            name = match.group("name")
            return name, bool(match.group("async")), bool(HOT_NAME_RE.search(name))
    return "<module>", False, False


def approximate_loop_scope(lines: Sequence[str], line_index: int) -> bool:
    start = max(0, line_index - 80)
    depth = 0
    for idx in range(line_index, start - 1, -1):
        text = re.sub(r"//.*", "", lines[idx])
        depth += text.count("}") - text.count("{")
        if depth <= 0 and LOOP_RE.search(text):
            return True
        if idx != line_index and depth < -2:
            break
    return False


def score_candidate(rule: Rule, test_code: bool, in_async: bool, in_hot: bool, in_loop: bool) -> int:
    severity = {"high": 50, "medium": 34, "low": 18}.get(rule.severity, 25)
    confidence = {"high": 30, "medium": 20, "low": 8}.get(rule.confidence, 12)
    score = severity + confidence
    if not test_code:
        score += 10
    if in_async and rule.category in {"concurrency", "availability", "resource-exhaustion", "lifecycle"}:
        score += 8
    if in_hot and rule.category in {"performance", "resource-exhaustion", "concurrency", "observability"}:
        score += 8
    if in_loop:
        score += 5
    return score


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or not should_scan(path):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_file(root: Path, path: Path, compiled_rules: Sequence[tuple[Rule, re.Pattern[str]]]) -> list[Candidate]:
    rel = path.relative_to(root)
    test_code = is_test_path(rel)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))

    candidates: list[Candidate] = []
    per_rule = Counter()
    suffix = path.suffix.lower() if path.suffix else path.name.lower()

    for rule, regex in compiled_rules:
        allowed = suffix in rule.extensions or path.name.lower() in rule.extensions
        if not allowed:
            continue
        if rule.prod_only and test_code:
            continue
        for match in regex.finditer(text):
            if per_rule[rule.id] >= MAX_MATCHES_PER_RULE_PER_FILE:
                break
            line_index = max(0, _offset_to_line(offsets, match.start()) - 1)
            line_no = line_index + 1
            column = match.start() - offsets[line_index] + 1
            function, in_async, in_hot = nearest_function(lines, line_index)
            in_loop = approximate_loop_scope(lines, line_index)
            context_start = max(0, line_index - rule.context_before)
            context_end = min(len(lines), line_index + rule.context_after + 1)
            context = [f"{idx + 1}: {lines[idx]}" for idx in range(context_start, context_end)]
            fingerprint_raw = f"{rule.id}\0{rel.as_posix()}\0{line_no}\0{clean_excerpt(lines[line_index] if lines else '')}"
            fingerprint = hashlib.sha256(fingerprint_raw.encode()).hexdigest()[:20]
            candidate_id = f"C-{fingerprint}"
            candidates.append(
                Candidate(
                    id=candidate_id,
                    fingerprint=fingerprint,
                    score=score_candidate(rule, test_code, in_async, in_hot, in_loop),
                    rule=rule.id,
                    category=rule.category,
                    severity_hint=rule.severity,
                    confidence_hint=rule.confidence,
                    path=rel.as_posix(),
                    line=line_no,
                    column=column,
                    function=function,
                    in_async=in_async,
                    in_hot_scope=in_hot,
                    in_loop_scope=in_loop,
                    test_code=test_code,
                    excerpt=clean_excerpt(lines[line_index] if lines else ""),
                    message=rule.message,
                    context_start=context_start + 1,
                    context_end=context_end,
                    context=context,
                )
            )
            per_rule[rule.id] += 1
    return candidates


def _offset_to_line(offsets: Sequence[int], offset: int) -> int:
    lo, hi = 0, len(offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if offsets[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid
    return max(1, lo)


def write_reports(root: Path, out: Path, sha: str, candidates: list[Candidate], inventory: list[dict[str, object]]) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    context_dir = out / "contexts"
    context_dir.mkdir()

    candidates.sort(key=lambda c: (-c.score, c.path, c.line, c.rule))
    counts_by_rule = Counter(c.rule for c in candidates)
    counts_by_category = Counter(c.category for c in candidates)
    counts_by_path = Counter(c.path for c in candidates)

    (out / "AUDITED_SHA").write_text(sha + "\n", encoding="utf-8")
    with (out / "candidates_index.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow([
            "rank", "id", "score", "severity_hint", "confidence_hint", "category", "rule",
            "path", "line", "column", "function", "async", "hot", "loop", "test", "excerpt", "message",
        ])
        for rank, item in enumerate(candidates, 1):
            writer.writerow([
                rank, item.id, item.score, item.severity_hint, item.confidence_hint, item.category,
                item.rule, item.path, item.line, item.column, item.function, int(item.in_async),
                int(item.in_hot_scope), int(item.in_loop_scope), int(item.test_code), item.excerpt, item.message,
            ])

    part_size = 250
    context_manifest = []
    for part_number, start in enumerate(range(0, len(candidates), part_size), 1):
        part = candidates[start : start + part_size]
        name = f"part-{part_number:04d}.jsonl"
        with (context_dir / name).open("w", encoding="utf-8") as handle:
            for item in part:
                handle.write(json.dumps(asdict(item), ensure_ascii=False, separators=(",", ":")) + "\n")
        context_manifest.append({"file": f"contexts/{name}", "rank_start": start + 1, "rank_end": start + len(part)})

    with (out / "inventory.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["path", "bytes", "lines", "extension", "test_code"])
        for row in sorted(inventory, key=lambda item: str(item["path"])):
            writer.writerow([row["path"], row["bytes"], row["lines"], row["extension"], int(bool(row["test_code"]))])

    with (out / "pattern_counts.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["rule", "count"])
        writer.writerows(counts_by_rule.most_common())

    summary = {
        "audited_sha": sha,
        "files_scanned": len(inventory),
        "lines_scanned": sum(int(row["lines"]) for row in inventory),
        "bytes_scanned": sum(int(row["bytes"]) for row in inventory),
        "candidate_count": len(candidates),
        "production_candidate_count": sum(1 for c in candidates if not c.test_code),
        "high_severity_hint_count": sum(1 for c in candidates if c.severity_hint == "high"),
        "high_confidence_hint_count": sum(1 for c in candidates if c.confidence_hint == "high"),
        "by_category": dict(counts_by_category.most_common()),
        "top_paths": counts_by_path.most_common(100),
        "context_manifest": context_manifest,
        "rules": [asdict(rule) for rule in RULES],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Ferrum Edge static audit candidate report",
        "",
        f"- Audited SHA: `{sha}`",
        f"- Files scanned: **{summary['files_scanned']:,}**",
        f"- Lines scanned: **{summary['lines_scanned']:,}**",
        f"- Candidates: **{summary['candidate_count']:,}**",
        f"- Production candidates: **{summary['production_candidate_count']:,}**",
        "",
        "These are review candidates, not automatically validated findings. Publication requires source-level verification and duplicate screening against the live open issue/PR backlog.",
        "",
        "## Categories",
        "",
    ]
    lines.extend(f"- `{category}`: {count}" for category, count in counts_by_category.most_common())
    lines.extend(["", "## Highest-volume rules", ""])
    lines.extend(f"- `{rule}`: {count}" for rule, count in counts_by_rule.most_common(50))
    (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"audit root does not exist: {root}")

    compiled_rules = [(rule, re.compile(rule.pattern, rule.flags)) for rule in RULES]
    candidates: list[Candidate] = []
    inventory: list[dict[str, object]] = []

    for path in iter_files(root):
        rel = path.relative_to(root)
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        text = raw.decode("utf-8", errors="replace")
        inventory.append({
            "path": rel.as_posix(),
            "bytes": len(raw),
            "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
            "extension": path.suffix.lower() or path.name,
            "test_code": is_test_path(rel),
        })
        candidates.extend(scan_file(root, path, compiled_rules))

    # One candidate per rule/path/line/excerpt fingerprint.
    unique: dict[str, Candidate] = {}
    for candidate in candidates:
        existing = unique.get(candidate.fingerprint)
        if existing is None or candidate.score > existing.score:
            unique[candidate.fingerprint] = candidate

    write_reports(root, args.out, args.sha, list(unique.values()), inventory)
    print(json.dumps({
        "audited_sha": args.sha,
        "files_scanned": len(inventory),
        "candidates": len(unique),
        "output": str(args.out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
