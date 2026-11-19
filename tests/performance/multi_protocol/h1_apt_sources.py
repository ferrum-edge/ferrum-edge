"""Rewrite the runner's Ubuntu apt source to the canonical archive host.

Used only by ``h1_apt_install.sh`` when the hosted runner's regional mirror
(for example ``us-east-2.ec2.archive.ubuntu.com``) stalls or serves unusable
indexes. Eligible regional Ubuntu mirror URIs are rewritten to
``https://archive.ubuntu.com/ubuntu/``; when a regional rewrite occurs,
compatible active lowercase portless ``http://archive.ubuntu.com/ubuntu/``
entries are also upgraded to HTTPS so APT does not reuse a plaintext Release
index for an overlapping suite. Every other field (``Types``, ``Suites``,
``Components``, ``Signed-By``, one-line ``[signed-by=...]`` options, comments)
is preserved, so GPG verification is never weakened and no unsigned repository
is introduced. Disabled deb822 stanzas (``Enabled: no``),
``security.ubuntu.com``, non-Ubuntu URIs (including third-party ``mirror+...``
lists), and any regional entry (stanza or line) with a suite that shares an
APT Release index with an entry that cannot be upgraded or has a different
policy, repository root, or layout keep their original URI for all of their
suites.

Usage: ``python3 h1_apt_sources.py SOURCE DEST``. Exit 0 after writing a
rewritten DEST, 3 when SOURCE has no regional Ubuntu mirror eligible for
canonical rewrite (DEST is not written), 2 on usage or parse errors.
"""
import os
import re
import sys
from pathlib import Path

CANONICAL = "https://archive.ubuntu.com/ubuntu/"

# Regional/cloud mirrors of the primary archive (``azure.``, ``us-east-2.ec2.``,
# ``<cc>.``) and Ubuntu mirror-list indirections used by hosted runner images.
# Schemes are matched exact-lowercase (APT selects acquisition methods by exact
# scheme name), hostnames case-insensitively, and paths case-sensitively.
# Require `mirror+file:` with empty authority (`///`) or path-only (`/`) for
# the local apt-mirrors.txt list so a remote `mirror://etc/...` URI never matches.
_MIRROR_URI = re.compile(
    r"^(?:https?://(?i:(?:[A-Za-z0-9-]+\.)+archive\.ubuntu\.com)(?::(?:80|443)?)?/ubuntu/?"
    r"|mirror\+file:(?:///|/)etc/apt/apt-mirrors\.txt"
    r"|mirror(?:\+https?)?://(?i:mirrors\.ubuntu\.com)/\S+)$",
    re.ASCII,
)
# Only portless lowercase `http://archive.ubuntu.com/ubuntu/` URIs (including
# empty `:`) share the portless `archive.ubuntu.com/ubuntu/` Release index and
# use APT's exact `http` method; explicit nonzero ports (`:80`, `:443`) and
# different host/scheme casing keep distinct Release filenames or methods.
_HTTP_CANONICAL = re.compile(r"^http://archive\.ubuntu\.com:?/ubuntu/?$")
# Structural deb822 fields that do not define per-Release/per-target merge
# policy; every other field (Signed-By, Snapshot, Include, Exclude,
# Architectures, Languages, Targets, PDiffs, By-Hash, Check-Valid-Until, etc.)
# must match before two entries can safely share an APT Release index.
_DEB822_NON_POLICY_FIELDS = frozenset({
    "types",
    "uris",
    "suites",
    "components",
    "enabled",
})
_POLICY_CONFLICT = object()
# APT's pkgTagSection::Scan splits on the first `:` and trims ASCII whitespace
# before the colon.
_DEB822_FIELD = re.compile(r"^([^:\r\n]+):(.*)$")
_LINE_SPLIT = re.compile(r"[^\n]*\n|[^\n]+")
_ONE_LINE_PREFIX = re.compile(r"^[ \t]*deb(?:-src)?[ \t]+")
_UNSAFE_FIELDS = frozenset({
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
})
# APT's StringToBool (apt-pkg/contrib/strutl.cc): `int Res = strtol(s, &end, 0)`
# compiled with glibc C23 `__isoc23_strtol` on Ubuntu 26.04 LP64 (64-bit signed
# long narrowed to 32-bit signed int), accepting strict C23 integer literals
# (decimal, 0-octal, 0x/0X hex, 0b/0B binary; no Python `_`, `0o`, or non-ASCII
# digits), followed by exact case-insensitive keyword sets.
_C_STRTOL_INT = re.compile(
    r"^[+-]?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)$"
)
_LONG_MIN = -(1 << 63)
_LONG_MAX = (1 << 63) - 1
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_ASCII_SPACE = frozenset(" \t\r\n\v\f")
_ASCII_SPACE_STR = " \t\r\n\v\f"
_APT_TRUE = frozenset({"yes", "true", "with", "on", "enable"})
_APT_FALSE = frozenset({"no", "false", "without", "off", "disable"})


def _parse_apt_bool(value):
    """Return True/False per APT's StringToBool, or None if unrecognized."""
    if not value:
        return None
    # C23 strtol skips leading ASCII whitespace but requires the entire
    # remaining string (no trailing whitespace) to parse as an integer.
    num_text = value.lstrip(_ASCII_SPACE_STR)
    if _C_STRTOL_INT.match(num_text):
        sign = -1 if num_text[0] == "-" else 1
        mag = num_text[1:] if num_text[0] in "+-" else num_text
        if mag.startswith(("0x", "0X")):
            val = sign * int(mag, 16)
        elif mag.startswith(("0b", "0B")):
            val = sign * int(mag, 2)
        elif mag.startswith("0") and len(mag) > 1:
            val = sign * int(mag, 8)
        else:
            val = sign * int(mag, 10)
        if val > _LONG_MAX:
            val = _LONG_MAX
        elif val < _LONG_MIN:
            val = _LONG_MIN
        res = ((val + (1 << 31)) % (1 << 32)) - (1 << 31)
        if res == 1:
            return True
        if res == 0:
            return False
        return None
    # Keyword comparisons use strcasecmp on the full string (no whitespace strip).
    low = value.lower()
    if low in _APT_TRUE:
        return True
    if low in _APT_FALSE:
        return False
    return None


def _is_apt_true(value):
    return _parse_apt_bool(value) is True


def _is_apt_false(value):
    return _parse_apt_bool(value) is False


def is_mirror(uri):
    return bool(_MIRROR_URI.match(uri))


def _is_http_canonical(uri):
    return bool(_HTTP_CANONICAL.match(uri))


def _should_rewrite_uri(uri, rewrite_mirrors=True, upgrade_http_canonical=False):
    return (rewrite_mirrors and is_mirror(uri)) or (
        upgrade_http_canonical and _is_http_canonical(uri)
    )


_ATOI_RE = re.compile(r"^[ \t\r\n\v\f]*([+-]?[0-9]+)")


def _apt_dequote_percent(raw):
    """Decode %HH escapes per APT's DeQuoteString, preserving raw bytes."""
    buf = bytearray()
    i, n = 0, len(raw)
    while i < n:
        if raw[i] == "%" and i + 2 < n and raw[i + 1] in _HEX_DIGITS and raw[i + 2] in _HEX_DIGITS:
            buf.append(int(raw[i + 1:i + 3], 16))
            i += 3
        else:
            buf.extend(raw[i].encode("utf-8", "surrogateescape"))
            i += 1
    return buf.decode("utf-8", "surrogateescape")


def _apt_quote_string(raw, bad):
    """Port of APT's `QuoteString` (`apt-pkg/contrib/strutl.cc:352-367`)."""
    bad_bytes = bad.encode("ascii")
    out = []
    for byte_val in raw.encode("utf-8", "surrogateescape"):
        if byte_val in bad_bytes or byte_val == 0x25 or byte_val <= 0x20 or byte_val >= 0x7F:
            out.append(f"%{byte_val:02x}")
        else:
            out.append(chr(byte_val))
    return "".join(out)


def _apt_uri_encode(part):
    """Port of APT's `pkgAcquire::URIEncode` (`apt-pkg/acquire.cc:65-69`)."""
    return _apt_quote_string(part, "+~ ")


def _parse_apt_uri(raw):
    """Port of APT's `::URI::CopyFrom` (`apt-pkg/contrib/strutl.cc:1648-1759`).

    Returns `(access, user, password, host, port, path)`.
    """
    n = len(raw)
    first_colon = raw.find(":")
    if first_colon == -1:
        first_colon = n
    single_slash = first_colon
    if first_colon + 3 < n and raw[first_colon + 1] == "/" and raw[first_colon + 2] == "/":
        single_slash += 3
    in_bracket = False
    while single_slash < n and (raw[single_slash] != "/" or in_bracket):
        if raw[single_slash] == "[":
            in_bracket = True
        elif in_bracket and raw[single_slash] == "]":
            in_bracket = False
        single_slash += 1

    access = raw[:first_colon]
    path = raw[single_slash:] if single_slash < n else ""
    if not path:
        path = "/"

    if first_colon + 2 < n and raw[first_colon + 1] == "/" and raw[first_colon + 2] == "/":
        start = first_colon + 3
    else:
        start = first_colon + 1
    if start >= n:
        return (access, "", "", "", 0, path)
    if start > single_slash:
        start = single_slash

    scan_from = min(start + 1, single_slash)
    at = raw.rfind("@", scan_from, single_slash)
    user = ""
    password = ""
    if at == -1:
        host = raw[start:single_slash] if start < single_slash else ""
    else:
        host = raw[at + 1:single_slash]
        second_colon = raw.find(":", scan_from, at)
        if second_colon == -1:
            user = _apt_dequote_percent(raw[start:at])
        else:
            user = _apt_dequote_percent(raw[start:second_colon])
            password = _apt_dequote_percent(raw[second_colon + 1:at])

    # Strip RFC 2732 `[]` brackets identically to strutl.cc:1723-1749.
    port_end = 0
    in_bracket = False
    host_chars = []
    for ch in host:
        if ch == "[":
            in_bracket = True
            continue
        if in_bracket and ch == "]":
            in_bracket = False
            port_end = len(host_chars)
            continue
        host_chars.append(ch)
    if in_bracket:
        return (access, user, password, "", 0, path)
    host = "".join(host_chars)

    port = 0
    pos = host.rfind(":")
    if pos != -1 and pos >= port_end:
        match = _ATOI_RE.match(host[pos + 1:])
        if match:
            # Match glibc LP64 `atoi` (`(int)strtol(s, NULL, 10)`) assigned to
            # `unsigned int URI::Port` (32-bit wrap; e.g. 4294967296 -> 0).
            val = int(match.group(1), 10)
            if val > _LONG_MAX:
                val = _LONG_MAX
            elif val < _LONG_MIN:
                val = _LONG_MIN
            port = val & 0xFFFFFFFF
        host = host[:pos]
    return (access, user, password, host, port, path)


def _format_apt_uri(access, user, password, host, port, path):
    """Port of APT's `::URI::operator string()` (`strutl.cc:1764-1806`)."""
    parts = []
    if access:
        parts.append(f"{access}:")
    if host:
        if access:
            parts.append("//")
        if user:
            parts.append(_apt_quote_string(user, ":/?#[]@"))
            if password:
                parts.append(":" + _apt_quote_string(password, ":/?#[]@"))
            parts.append("@")
        if access and ("/" in host or ":" in host):
            parts.append(f"[{host}]")
        else:
            parts.append(host)
        if port != 0:
            parts.append(f":{port}")
    if path:
        if not path.startswith("/"):
            parts.append("/" + path)
        else:
            parts.append(path)
    return "".join(parts)


def _full_repo_uri(uri):
    """Return APT's normalized full `REPO_URI` (preserving exact scheme case and userinfo)."""
    base = uri if uri.endswith("/") else uri + "/"
    access, user, password, host, port, path = _parse_apt_uri(base)
    return _format_apt_uri(access, user, password, host, port, path)


_URI_FILENAME_BAD = r'\|{}[]<>"^~_=!@#$%^&*'


def _release_index_key(uri, suite):
    """Port of APT's `URItoFileName(constructMetaIndexURI(FixupURI(uri), suite, "Release"))`.

    Matches `apt-pkg/deb/debmetaindex.cc:165-174` and `apt-pkg/contrib/strutl.cc:521-533`.
    """
    base = _full_repo_uri(uri)
    if not base.endswith("/"):
        base += "/"
    if suite == "/":
        meta_uri = base + "Release"
    elif suite.endswith("/"):
        meta_uri = base + _apt_uri_encode(suite) + "Release"
    else:
        meta_uri = base + "dists/" + _apt_uri_encode(suite) + "/Release"
    _access, _user, _password, host, port, path = _parse_apt_uri(meta_uri)
    stripped = _format_apt_uri("", "", "", host, port, path)
    return _apt_quote_string(stripped, _URI_FILENAME_BAD).replace("/", "_")


def _suite_policy(policy, uri, suite):
    """Conservative merge-compatibility key: entry options, layout, full REPO_URI, and RELEASE."""
    return (policy, suite.endswith("/"), _full_repo_uri(uri), "" if suite == "/" else suite)


_CANONICAL_HOST, _CANONICAL_PORT = _parse_apt_uri(CANONICAL)[3:5]
_CANONICAL_FILENAME_PREFIX = f"{_CANONICAL_HOST}_"
_CANONICAL_WILDCARD = object()


def _has_arch_var(text):
    return "$(ARCH)" in text


def _register_entry_keys(release_policies, uris, suites, policy):
    for uri in uris:
        access, _user, _password, host, port, _path = _parse_apt_uri(uri)
        # Match APT's exact lowercase method name (`https`); capitalized
        # schemes like `HTTPS:` select a different/missing method in APT.
        is_https = access == "https"
        upgradeable_http = _is_http_canonical(uri)
        if _has_arch_var(uri) and host == _CANONICAL_HOST and port == _CANONICAL_PORT:
            release_policies[_CANONICAL_WILDCARD] = _POLICY_CONFLICT
        for suite in suites:
            if _has_arch_var(suite) and host == _CANONICAL_HOST and port == _CANONICAL_PORT:
                release_policies[_CANONICAL_WILDCARD] = _POLICY_CONFLICT
            key = _release_index_key(uri, suite)
            # Any non-HTTPS entry that is not an upgradeable portless HTTP
            # canonical URI blocks merges onto its effective Release filename
            # so APT neither hits a policy conflict nor reuses non-HTTPS transport.
            if not is_https and not upgradeable_http:
                release_policies[key] = _POLICY_CONFLICT
                continue
            post_uri = CANONICAL if upgradeable_http else uri
            effective_policy = _suite_policy(policy, post_uri, suite)
            existing = release_policies.get(key)
            if existing is None:
                release_policies[key] = effective_policy
            elif existing != effective_policy:
                release_policies[key] = _POLICY_CONFLICT


def _canonical_keys_compatible(release_policies, suites, policy):
    if _CANONICAL_WILDCARD in release_policies:
        return False
    has_existing_canonical = any(
        isinstance(k, str) and k.startswith(_CANONICAL_FILENAME_PREFIX)
        for k in release_policies
    )
    for suite in suites:
        if _has_arch_var(suite) and has_existing_canonical:
            return False
        key = _release_index_key(CANONICAL, suite)
        existing = release_policies.get(key)
        if existing is not None and existing != _suite_policy(policy, CANONICAL, suite):
            return False
    return True


def _register_canonical_keys(release_policies, suites, policy):
    for suite in suites:
        if _has_arch_var(suite):
            release_policies[_CANONICAL_WILDCARD] = _POLICY_CONFLICT
        key = _release_index_key(CANONICAL, suite)
        effective_policy = _suite_policy(policy, CANONICAL, suite)
        existing = release_policies.get(key)
        if existing is None:
            release_policies[key] = effective_policy
        elif existing != effective_policy:
            release_policies[key] = _POLICY_CONFLICT


_ASCII_TOKEN = re.compile(r"[^ \t\r\n\v\f]+")


def _rewrite_uris(value, rewrite_mirrors=True, upgrade_http_canonical=False):
    """Rewrite one URIs field value on ASCII whitespace boundaries; return (value, changed)."""
    tokens = _ASCII_TOKEN.findall(value)
    rewritten, changed = [], False
    for token in tokens:
        if _should_rewrite_uri(token, rewrite_mirrors, upgrade_http_canonical):
            token, changed = CANONICAL, True
        if token not in rewritten:
            rewritten.append(token)
    if not changed:
        return value, False
    leading = value[:len(value) - len(value.lstrip(_ASCII_SPACE_STR))]
    return leading + " ".join(rewritten), True


def _apt_dequote_word(raw, lineno=None):
    """Decode %HH escapes and strip double quotes like APT's ParseQuoteWord.

    Preserves raw bytes via UTF-8/surrogateescape so percent-decoded non-ASCII
    bytes match APT's byte-level `QuoteString`/`URItoFileName` encoding.
    Refuses ASCII control characters (including raw or `%00` NUL bytes), which
    can truncate C-string comparisons or desync option/URI boundaries in APT.
    """
    loc = f"line {lineno}: " if lineno is not None else ""
    buf = bytearray()
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "%" and i + 2 < n and raw[i + 1] in _HEX_DIGITS and raw[i + 2] in _HEX_DIGITS:
            byte_val = int(raw[i + 1:i + 3], 16)
            if byte_val < 0x20 or byte_val == 0x7F:
                raise ValueError(f"{loc}apt token contains percent-encoded control byte 0x{byte_val:02x}")
            buf.append(byte_val)
            i += 3
            continue
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(f"{loc}apt token contains control character")
        if ch != '"':
            buf.extend(ch.encode("utf-8", "surrogateescape"))
        i += 1
    return buf.decode("utf-8", "surrogateescape")


def _decode_one_line_options(opts_bracket, lineno=None):
    """Parse APT one-line `[k=v ...]` options per ParseQuoteWord + sourcelist.cc."""
    loc = f"line {lineno}: " if lineno is not None else ""
    inner = opts_bracket[1:-1]
    pairs = []
    i, n = 0, len(inner)
    while True:
        while i < n and inner[i] in _ASCII_SPACE:
            i += 1
        if i >= n:
            break
        start = i
        while i < n and inner[i] not in _ASCII_SPACE:
            if inner[i] == '"':
                close = inner.find('"', i + 1)
                if close == -1:
                    raise ValueError(f"{loc}unterminated quote in apt option bracket")
                i = close + 1
            else:
                i += 1
        option = _apt_dequote_word(inner[start:i], lineno)
        # APT's sourcelist.cc strips a trailing decoded `]` (including `%5d`),
        # so fail closed on any decoded `]` inside an option token.
        if "]" in option:
            raise ValueError(f"{loc}ambiguous ']' in apt option")
        if "=" not in option:
            raise ValueError(f"{loc}malformed apt option (missing '=')")
        key, value = option.split("=", 1)
        if not key:
            raise ValueError(f"{loc}empty apt option key")
        pairs.append((key, value))
    return pairs


def _check_one_line_options(opts_bracket, lineno=None):
    if not opts_bracket:
        return
    loc = f"line {lineno}: " if lineno is not None else ""
    # APT stores one-line option names case-sensitively (`sourcelist.cc:240`)
    # and looks up exact lowercase trust keys (`debmetaindex.cc:1236,1444`).
    effective = {}
    for key, value in _decode_one_line_options(opts_bracket, lineno):
        effective[key] = value
    for unsafe in _UNSAFE_FIELDS:
        if unsafe in effective and _is_apt_true(effective[unsafe]):
            raise ValueError(
                f"{loc}source sets unsafe option [{unsafe}]; refusing to rewrite"
            )


def _strip_one_line_comment(body):
    """Port of APT's `ParseFileOldStyle` comment strip (`sourcelist.cc:385-399`).

    Returns `(code_part, comment_part)`: strips from the first `#` whose
    preceding prefix does not have more `[` than `]` (ignoring double quotes,
    matching APT).
    """
    pos = body.find("#")
    while pos != -1:
        if body.count("[", 0, pos) > body.count("]", 0, pos):
            pos = body.find("#", pos + 1)
            continue
        return body[:pos], body[pos:]
    return body, ""


def _parse_one_line(raw_body, lineno=None):
    """Parse `(head, opts_bracket, raw_uri, decoded_uri, suite, tail)` from a one-line deb entry."""
    loc = f"line {lineno}: " if lineno is not None else ""
    body, comment = _strip_one_line_comment(raw_body)
    prefix = _ONE_LINE_PREFIX.match(body)
    if not prefix:
        return None
    pos, n = prefix.end(), len(body)
    opts_bracket = None
    if pos < n and body[pos] == "[":
        i = pos + 1
        end_bracket = -1
        while i < n:
            if body[i] == '"':
                close = body.find('"', i + 1)
                if close == -1:
                    raise ValueError(f"{loc}unterminated quote in apt option bracket")
                i = close + 1
                continue
            if body[i] == "[":
                raise ValueError(f"{loc}nested '[' in apt option bracket")
            if body[i] == "]":
                end_bracket = i
                break
            i += 1
        if end_bracket == -1:
            raise ValueError(f"{loc}unterminated apt option bracket")
        opts_bracket = body[pos:end_bracket + 1]
        # APT only accepts an adjacent URI after `]` when `]` starts a word
        # (preceded by ASCII whitespace or immediately after `[`). A mid-word
        # `]` such as `[signed-by=K]http://...` is consumed as option text by APT.
        bracket_word_start = (end_bracket == pos + 1) or (body[end_bracket - 1] in _ASCII_SPACE)
        pos = end_bracket + 1
        ws_start = pos
        while pos < n and body[pos] in _ASCII_SPACE:
            pos += 1
        if pos == ws_start and not bracket_word_start:
            raise ValueError(f"{loc}malformed apt source line after option bracket")
    uri_start = pos
    while pos < n and body[pos] not in _ASCII_SPACE:
        if body[pos] == '"':
            close = body.find('"', pos + 1)
            if close == -1:
                raise ValueError(f"{loc}unterminated quote in apt URI")
            pos = close + 1
        elif body[pos] == "[":
            close = body.find("]", pos + 1)
            if close == -1:
                raise ValueError(f"{loc}unterminated '[' in apt URI")
            pos = close + 1
        else:
            pos += 1
    if pos == uri_start:
        return None
    raw_uri = body[uri_start:pos]
    decoded_uri = _apt_dequote_word(raw_uri, lineno)
    tail = body[pos:] + comment
    # Extract the suite token from the comment-stripped tail per ParseQuoteWord.
    suite_scan = body[pos:].lstrip(_ASCII_SPACE_STR)
    suite = None
    if suite_scan:
        j, m = 0, len(suite_scan)
        while j < m and suite_scan[j] not in _ASCII_SPACE:
            if suite_scan[j] == '"':
                close = suite_scan.find('"', j + 1)
                if close == -1:
                    raise ValueError(f"{loc}unterminated quote in apt suite")
                j = close + 1
            elif suite_scan[j] == "[":
                close = suite_scan.find("]", j + 1)
                if close == -1:
                    raise ValueError(f"{loc}unterminated '[' in apt suite")
                j = close + 1
            else:
                j += 1
        if j > 0:
            suite = _apt_dequote_word(suite_scan[:j], lineno)
    return body[:uri_start], opts_bracket, raw_uri, decoded_uri, suite, tail


def _one_line_policy(opts_bracket, lineno=None):
    if not opts_bracket:
        return ()
    effective = {}
    for key, value in _decode_one_line_options(opts_bracket, lineno):
        effective[key] = value
    return tuple(sorted(effective.items()))


def _inspect_deb822_stanza(lines, start_lineno=1):
    """Validate one deb822 stanza and return `(active, uris, suites, policy)`."""
    fields = {}
    active_field = None
    for offset, line in enumerate(lines):
        lineno = start_lineno + offset
        body = line.rstrip("\r\n")
        if body.startswith("#"):
            continue
        if body[:1] in (" ", "\t", "\v", "\f"):
            # Preserve raw continuation content (including `.` lines) so boolean
            # fields match APT's `pkgTagSection::Find` / `FindB` semantics.
            if active_field is not None:
                fields[active_field].append(body)
            continue
        field = _DEB822_FIELD.match(body)
        if not field:
            raise ValueError(f"line {lineno}: malformed deb822 field line")
        active_field = field.group(1).rstrip(" \t\v\f").lower()
        fields[active_field] = [field.group(2)]

    def field_value(name):
        # Match APT pkgTagSection::Scan (tagfile.cc:566-573): trim trailing
        # ASCII whitespace, then skip leading ASCII whitespace after `:` except
        # stop at `\n` unless followed by an ASCII space `' '` (0x20).
        raw_block = "\n".join(fields[name]).rstrip(_ASCII_SPACE_STR)
        pos, n = 0, len(raw_block)
        while pos < n and raw_block[pos] in _ASCII_SPACE:
            if raw_block[pos] == "\n" and (pos + 1 >= n or raw_block[pos + 1] != " "):
                break
            pos += 1
        return raw_block[pos:]

    # APT skips stanzas with Enabled set to a false boolean spelling.
    if "enabled" in fields and _is_apt_false(field_value("enabled")):
        return False, [], [], None

    for unsafe in _UNSAFE_FIELDS:
        if unsafe in fields and _is_apt_true(field_value(unsafe)):
            raise ValueError(
                f"stanza at line {start_lineno}: sets unsafe field {unsafe}; refusing to rewrite"
            )

    uris = _ASCII_TOKEN.findall(field_value("uris")) if "uris" in fields else []
    suites = _ASCII_TOKEN.findall(field_value("suites")) if "suites" in fields else []
    policy = tuple(
        sorted(
            (name, field_value(name))
            for name in fields
            if name not in _DEB822_NON_POLICY_FIELDS
        )
    )
    return True, uris, suites, policy


def _rewrite_deb822_stanza_uris(lines, rewrite_mirrors=True, upgrade_http_canonical=False):
    out, changed, in_uris = [], False, False
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if body.startswith("#"):
            out.append(body + ending)
            continue
        if body[:1] in (" ", "\t", "\v", "\f"):
            if in_uris and body.strip():
                value, hit = _rewrite_uris(body, rewrite_mirrors, upgrade_http_canonical)
                changed |= hit
                body = value
            out.append(body + ending)
            continue
        field = _DEB822_FIELD.match(body)
        if field:
            in_uris = field.group(1).rstrip(" \t\v\f").lower() == "uris"
            if in_uris:
                value, hit = _rewrite_uris(field.group(2), rewrite_mirrors, upgrade_http_canonical)
                changed |= hit
                body = f"{field.group(1)}:{value}"
        out.append(body + ending)
    return out, changed


def rewrite_deb822(text):
    # Split into blank-line chunks and stanzas. APT's pkgTagSection::Scan ends
    # a record only on an empty line (\n or \r\n), NOT on a whitespace-only line.
    chunks = []
    stanza = []
    stanza_start = 1
    for lineno, line in enumerate(_LINE_SPLIT.findall(text), start=1):
        body = line.rstrip("\r\n")
        if "\r" in body:
            raise ValueError(f"line {lineno}: apt source contains bare CR character")
        if body == "":
            if stanza:
                chunks.append(("stanza", stanza_start, stanza))
                stanza = []
            chunks.append(("blank", lineno, [line]))
        else:
            if not stanza:
                stanza_start = lineno
            stanza.append(line)
    if stanza:
        chunks.append(("stanza", stanza_start, stanza))

    # Pass 1: validate every active stanza and record signing policies keyed by
    # APT's effective Release filename across ALL active entries.
    inspected = []
    release_policies = {}
    for kind, start_lineno, lines in chunks:
        if kind != "stanza":
            inspected.append((kind, lines, None))
            continue
        info = _inspect_deb822_stanza(lines, start_lineno)
        active, uris, suites, policy = info
        if active:
            _register_entry_keys(release_policies, uris, suites, policy)
        inspected.append((kind, lines, info))

    # Fixpoint: if an active multi-suite portless HTTP canonical stanza cannot
    # be upgraded (because any of its suites is blocked/conflicting), it will
    # remain on HTTP, so block all of its suites on CANONICAL to prevent
    # plaintext Release-index reuse by a rewritten HTTPS mirror.
    changed_block = True
    while changed_block:
        changed_block = False
        for kind, _lines, info in inspected:
            if kind != "stanza":
                continue
            active, uris, suites, policy = info
            if not active or not any(_is_http_canonical(u) for u in uris):
                continue
            if not _canonical_keys_compatible(release_policies, suites, policy):
                for suite in suites:
                    key = _release_index_key(CANONICAL, suite)
                    if release_policies.get(key) is not _POLICY_CONFLICT:
                        release_policies[key] = _POLICY_CONFLICT
                        changed_block = True

    # Pass 2: decide which regional-mirror stanzas can rewrite onto CANONICAL
    # without colliding with a different signing policy or un-upgradeable
    # non-HTTPS entry on the destination Release index.
    rewritten_indices = set()
    for idx, (kind, _lines, info) in enumerate(inspected):
        if kind != "stanza":
            continue
        active, uris, suites, policy = info
        if not active or not any(is_mirror(u) for u in uris):
            continue
        if not _canonical_keys_compatible(release_policies, suites, policy):
            continue
        rewritten_indices.add(idx)
        _register_canonical_keys(release_policies, suites, policy)

    if not rewritten_indices:
        return text, False

    # Pass 3: rewrite eligible regional stanzas and upgrade compatible active
    # portless HTTP canonical stanzas to HTTPS (leaving disabled stanzas and
    # conflicting entries untouched so distinct Release indexes are preserved).
    out = []
    for idx, (kind, lines, info) in enumerate(inspected):
        if kind != "stanza":
            out.extend(lines)
            continue
        active, uris, suites, policy = info
        if idx in rewritten_indices:
            new_lines, _ = _rewrite_deb822_stanza_uris(
                lines, rewrite_mirrors=True, upgrade_http_canonical=True
            )
            out.extend(new_lines)
        elif (
            active
            and any(_is_http_canonical(u) for u in uris)
            and _canonical_keys_compatible(release_policies, suites, policy)
        ):
            new_lines, _ = _rewrite_deb822_stanza_uris(
                lines, rewrite_mirrors=False, upgrade_http_canonical=True
            )
            out.extend(new_lines)
        else:
            out.extend(lines)
    return "".join(out), True


def rewrite_one_line(text):
    # Pass 1: validate every active line and record Release-index policies
    # across ALL active entries (including userinfo/flat-suite variants).
    records = []
    release_policies = {}
    for lineno, line in enumerate(_LINE_SPLIT.findall(text), start=1):
        body = line.rstrip("\r\n")
        if "\r" in body:
            raise ValueError(f"line {lineno}: apt source contains bare CR character")
        ending = line[len(body):]
        stripped = body.lstrip(_ASCII_SPACE_STR)
        if not stripped or stripped.startswith("#"):
            records.append(("raw", line, None))
            continue
        parsed = _parse_one_line(body, lineno)
        if not parsed:
            raise ValueError(f"line {lineno}: unsupported or malformed apt source entry")
        head, opts_bracket, _raw_uri, decoded_uri, suite, tail = parsed
        _check_one_line_options(opts_bracket, lineno)
        policy = _one_line_policy(opts_bracket, lineno)
        suites = [suite] if suite else []
        _register_entry_keys(release_policies, [decoded_uri], suites, policy)
        records.append(("entry", (line, head, decoded_uri, tail, ending), (suites, policy)))

    # Pass 2: select regional-mirror entries that can safely map onto CANONICAL
    # without colliding with a distinct signing policy or un-upgradeable
    # non-HTTPS entry on the destination Release index.
    rewritten_indices = set()
    for idx, (kind, payload, meta) in enumerate(records):
        if kind != "entry":
            continue
        _orig_line, _head, decoded_uri, _tail, _ending = payload
        suites, policy = meta
        if not is_mirror(decoded_uri):
            continue
        if not _canonical_keys_compatible(release_policies, suites, policy):
            continue
        rewritten_indices.add(idx)
        _register_canonical_keys(release_policies, suites, policy)

    if not rewritten_indices:
        return text, False

    # Pass 3: rewrite eligible regional entries and upgrade compatible active
    # portless HTTP canonical entries to HTTPS while preserving conflicts.
    out = []
    for idx, (kind, payload, meta) in enumerate(records):
        if kind != "entry":
            out.append(payload)
            continue
        orig_line, head, decoded_uri, tail, ending = payload
        suites, policy = meta
        if idx in rewritten_indices or (
            _is_http_canonical(decoded_uri)
            and _canonical_keys_compatible(release_policies, suites, policy)
        ):
            out.append(head + CANONICAL + tail + ending)
        else:
            out.append(orig_line)
    return "".join(out), True


def rewrite(text, deb822):
    """Return (rewritten text, changed). Refuses active entries disabling signatures."""
    for ch in text:
        code = ord(ch)
        if (code < 0x20 and ch not in "\t\r\n") or code == 0x7F:
            raise ValueError(f"apt source contains unsupported control character 0x{code:02x}")
    return rewrite_deb822(text) if deb822 else rewrite_one_line(text)


def main(argv):
    if len(argv) != 3:
        print("usage: h1_apt_sources.py SOURCE DEST", file=sys.stderr)
        return 2
    source, dest = Path(argv[1]), Path(argv[2])
    deb822 = source.suffix == ".sources"
    if deb822 != (dest.suffix == ".sources"):
        print("SOURCE and DEST must use the same apt source format suffix", file=sys.stderr)
        return 2
    try:
        with source.open("r", encoding="utf-8", newline="") as handle:
            raw = handle.read()
        text, changed = rewrite(raw, deb822)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"cannot rewrite {source}: {error}", file=sys.stderr)
        return 2
    if not changed:
        print(
            f"{source} has no regional Ubuntu archive mirror eligible for canonical rewrite",
            file=sys.stderr,
        )
        return 3
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
