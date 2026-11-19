"""Rewrite the runner's Ubuntu apt source to the canonical archive host.

Used only by ``h1_apt_install.sh`` when the hosted runner's regional mirror
(for example ``us-east-2.ec2.archive.ubuntu.com``) stalls or serves unusable
indexes. Only the mirror URI changes: every other field (``Types``,
``Suites``, ``Components``, ``Signed-By``, one-line ``[signed-by=...]``
options, comments) is kept byte for byte, so GPG verification is never
weakened and no unsigned repository is introduced. Disabled deb822 stanzas
(``Enabled: no``), ``security.ubuntu.com``, and any non-Ubuntu URI (including
third-party ``mirror+...`` lists) are left as they are.

Usage: ``python3 h1_apt_sources.py SOURCE DEST``. Exit 0 after writing a
rewritten DEST, 3 when SOURCE names no regional Ubuntu mirror (DEST is not
written), 2 on usage or parse errors.
"""
import re
import sys
from pathlib import Path

CANONICAL = "http://archive.ubuntu.com/ubuntu/"

# Regional/cloud mirrors of the primary archive (``azure.``, ``us-east-2.ec2.``,
# ``<cc>.``) and Ubuntu mirror-list indirections used by hosted runner images.
# Require `mirror+file:` with empty authority (`///`) or path-only (`/`) for
# the local apt-mirrors.txt list so a remote `mirror://etc/...` URI never matches.
_MIRROR_URI = re.compile(
    r"^(?:https?://(?:[A-Za-z0-9-]+\.)+archive\.ubuntu\.com/ubuntu/?"
    r"|mirror\+file:(?:///|/)etc/apt/apt-mirrors\.txt"
    r"|mirror(?:\+https?)?://mirrors\.ubuntu\.com/\S+)$"
)
# APT's pkgTagSection::Scan splits on the first `:` and trims ASCII whitespace
# before the colon.
_DEB822_FIELD = re.compile(r"^([^:\r\n]+):(.*)$")
_LINE_SPLIT = re.compile(r"[^\n]*\n|[^\n]+")
_ONE_LINE_PREFIX = re.compile(r"^\s*deb(?:-src)?[ \t]+")
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
# digits), followed by case-insensitive keyword sets.
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
    s = value.strip(_ASCII_SPACE_STR)
    if not s:
        return None
    if _C_STRTOL_INT.match(s):
        sign = -1 if s[0] == "-" else 1
        mag = s[1:] if s[0] in "+-" else s
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
    low = s.lower()
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


def _rewrite_uris(value):
    """Rewrite one URIs field value; return (value, changed)."""
    tokens = value.split()
    rewritten, changed = [], False
    for token in tokens:
        if is_mirror(token):
            token, changed = CANONICAL, True
        if token not in rewritten:
            rewritten.append(token)
    if not changed:
        return value, False
    leading = value[:len(value) - len(value.lstrip())]
    return leading + " ".join(rewritten), True


def _apt_dequote_word(raw):
    """Decode %HH escapes and strip double quotes like APT's ParseQuoteWord.

    Refuses embedded NUL bytes (raw or `%00`), which would truncate C-string
    comparisons inside APT's `StringToBool`.
    """
    chars = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "%" and i + 2 < n and raw[i + 1] in _HEX_DIGITS and raw[i + 2] in _HEX_DIGITS:
            byte_val = int(raw[i + 1:i + 3], 16)
            if byte_val == 0:
                raise ValueError(f"apt token {raw!r} contains percent-encoded NUL byte")
            chars.append(chr(byte_val))
            i += 3
            continue
        if ch == "\x00":
            raise ValueError(f"apt token {raw!r} contains embedded NUL byte")
        if ch != '"':
            chars.append(ch)
        i += 1
    return "".join(chars)


def _decode_one_line_options(opts_bracket):
    """Parse APT one-line `[k=v ...]` options per ParseQuoteWord + sourcelist.cc."""
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
                    raise ValueError(f"unterminated quote in apt option bracket {opts_bracket!r}")
                i = close + 1
            else:
                i += 1
        option = _apt_dequote_word(inner[start:i])
        if "=" not in option:
            raise ValueError(f"malformed apt option {option!r} in {opts_bracket!r}")
        key, value = option.split("=", 1)
        if not key:
            raise ValueError(f"empty apt option key in {opts_bracket!r}")
        pairs.append((key, value))
    return pairs


def _check_one_line_options(opts_bracket):
    if not opts_bracket:
        return
    for key, value in _decode_one_line_options(opts_bracket):
        if key.lower() in _UNSAFE_FIELDS and _is_apt_true(value):
            raise ValueError(
                f"source sets [{key}={value}]; refusing to rewrite unsafe source"
            )


def _parse_one_line(body):
    """Parse `(head, opts_bracket, raw_uri, decoded_uri, tail)` from a one-line deb entry."""
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
                    raise ValueError(f"unterminated quote in apt option bracket on line {body!r}")
                i = close + 1
                continue
            if body[i] == "[":
                raise ValueError(f"nested '[' in apt option bracket on line {body!r}")
            if body[i] == "]":
                end_bracket = i
                break
            i += 1
        if end_bracket == -1:
            raise ValueError(f"unterminated apt option bracket on line {body!r}")
        opts_bracket = body[pos:end_bracket + 1]
        pos = end_bracket + 1
        ws_start = pos
        while pos < n and body[pos] in _ASCII_SPACE:
            pos += 1
        if pos == ws_start:
            raise ValueError(f"malformed apt source line after option bracket: {body!r}")
    uri_start = pos
    while pos < n and body[pos] not in _ASCII_SPACE:
        if body[pos] == '"':
            close = body.find('"', pos + 1)
            if close == -1:
                raise ValueError(f"unterminated quote in apt URI on line {body!r}")
            pos = close + 1
        elif body[pos] == "[":
            close = body.find("]", pos + 1)
            if close == -1:
                raise ValueError(f"unterminated '[' in apt URI on line {body!r}")
            pos = close + 1
        else:
            pos += 1
    if pos == uri_start:
        return None
    raw_uri = body[uri_start:pos]
    decoded_uri = _apt_dequote_word(raw_uri)
    return body[:uri_start], opts_bracket, raw_uri, decoded_uri, body[pos:]


def _process_deb822_stanza(lines):
    """Inspect and rewrite a single deb822 stanza; return (lines, changed)."""
    fields = {}
    active_field = None
    for line in lines:
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
            raise ValueError(f"malformed deb822 line: {body!r}")
        active_field = field.group(1).rstrip(" \t\v\f").lower()
        fields[active_field] = [field.group(2)]

    def field_value(name):
        return "\n".join(fields[name]).strip(_ASCII_SPACE_STR)

    # APT skips stanzas with Enabled set to a false boolean spelling.
    if "enabled" in fields and _is_apt_false(field_value("enabled")):
        return lines, False

    for unsafe in _UNSAFE_FIELDS:
        if unsafe in fields and _is_apt_true(field_value(unsafe)):
            raw = field_value(unsafe)
            raise ValueError(
                f"source sets {unsafe}: {raw}; refusing to rewrite unsafe source"
            )

    out, changed, in_uris = [], False, False
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if body.startswith("#"):
            out.append(body + ending)
            continue
        if body[:1] in (" ", "\t", "\v", "\f"):
            if in_uris and body.strip():
                value, hit = _rewrite_uris(body)
                changed |= hit
                body = value
            out.append(body + ending)
            continue
        field = _DEB822_FIELD.match(body)
        if field:
            in_uris = field.group(1).rstrip(" \t\v\f").lower() == "uris"
            if in_uris:
                value, hit = _rewrite_uris(field.group(2))
                changed |= hit
                body = f"{field.group(1)}:{value}"
        out.append(body + ending)
    return out, changed


def rewrite_deb822(text):
    out, changed = [], False
    stanza = []
    # APT's pkgTagSection::Scan ends a record only on an empty line (\n or \r\n),
    # NOT on a whitespace-only continuation line such as "  \n".
    for line in _LINE_SPLIT.findall(text):
        if line.rstrip("\r\n") == "":
            if stanza:
                rewritten, hit = _process_deb822_stanza(stanza)
                out.extend(rewritten)
                changed |= hit
                stanza = []
            out.append(line)
        else:
            stanza.append(line)
    if stanza:
        rewritten, hit = _process_deb822_stanza(stanza)
        out.extend(rewritten)
        changed |= hit
    return "".join(out), changed


def rewrite_one_line(text):
    out, changed = [], False
    for line in _LINE_SPLIT.findall(text):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if body.lstrip().startswith("#") or not body.strip():
            out.append(body + ending)
            continue
        parsed = _parse_one_line(body)
        if parsed:
            head, opts_bracket, _raw_uri, decoded_uri, tail = parsed
            _check_one_line_options(opts_bracket)
            if is_mirror(decoded_uri):
                body = head + CANONICAL + tail
                changed = True
        out.append(body + ending)
    return "".join(out), changed


def rewrite(text, deb822):
    """Return (rewritten text, changed). Refuses active entries disabling signatures."""
    if "\x00" in text:
        raise ValueError("apt source contains embedded NUL byte")
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
        print(f"{source} names no regional Ubuntu archive mirror", file=sys.stderr)
        return 3
    with dest.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
