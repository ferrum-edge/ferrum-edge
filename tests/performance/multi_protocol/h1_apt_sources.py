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
import shlex
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
_DEB822_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):(.*)$")
_ONE_LINE = re.compile(
    r"^(?P<head>\s*deb(?:-src)?\s+(?:(?P<opts>\[[^\]]*\])\s+)?)(?P<uri>\S+)(?P<tail>(?:\s.*)?)$"
)
_UNSAFE_FIELDS = frozenset({
    "trusted",
    "allow-insecure",
    "allow-weak",
    "allow-downgrade-to-insecure",
})
# APT's StringToBool spellings (apt-pkg/contrib/strutl.cc): strtol(val, 0) == 0|1
# (including C octal such as 01 / 00, hex 0x1, signed +1) plus keyword sets.
_C_OCTAL = re.compile(r"^[+-]?0[0-7]+$")
_APT_TRUE = frozenset({"yes", "true", "with", "on", "enable"})
_APT_FALSE = frozenset({"no", "false", "without", "off", "disable"})


def _parse_apt_bool(value):
    """Return True/False per APT's StringToBool, or None if unrecognized."""
    s = value.strip()
    if not s:
        return None
    try:
        num = int(s, 8) if _C_OCTAL.match(s) else int(s, 0)
    except ValueError:
        num = None
    if num == 1:
        return True
    if num == 0:
        return False
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


def _decode_one_line_options(opts_bracket):
    """Parse APT one-line `[k=v ...]` options, honoring quoted values."""
    inner = opts_bracket[1:-1].strip()
    if not inner:
        return []
    # APT accepts quoted values such as trusted="yes" or [signed-by="/path"].
    try:
        tokens = shlex.split(inner, posix=True)
    except ValueError as error:
        raise ValueError(f"malformed apt option bracket {opts_bracket!r}: {error}") from error
    pairs = []
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        pairs.append((key.strip(), value.strip()))
    return pairs


def _check_one_line_options(opts_bracket):
    if not opts_bracket:
        return
    for key, value in _decode_one_line_options(opts_bracket):
        if key.lower() in _UNSAFE_FIELDS and _is_apt_true(value):
            raise ValueError(
                f"source sets [{key}={value}]; refusing to rewrite unsafe source"
            )


def _process_deb822_stanza(lines):
    """Inspect and rewrite a single deb822 stanza; return (lines, changed)."""
    fields = {}
    active_field = None
    for line in lines:
        body = line.rstrip("\r\n")
        if body.startswith("#") or not body.strip():
            continue
        field = None if body.startswith((" ", "\t")) else _DEB822_FIELD.match(body)
        if field:
            active_field = field.group(1).lower()
            val = field.group(2).strip()
            fields[active_field] = [val] if val else []
        elif active_field and body[:1] in (" ", "\t") and body.strip() != ".":
            fields[active_field].append(body.strip())

    # APT skips stanzas with Enabled set to a false boolean spelling.
    if "enabled" in fields and _is_apt_false(" ".join(fields["enabled"])):
        return lines, False

    for unsafe in _UNSAFE_FIELDS:
        if unsafe in fields and _is_apt_true(" ".join(fields[unsafe])):
            raw = " ".join(fields[unsafe])
            raise ValueError(
                f"source sets {unsafe}: {raw}; refusing to rewrite unsafe source"
            )

    out, changed, in_uris = [], False, False
    for line in lines:
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if body.startswith("#") or not body.strip():
            out.append(body + ending)
            continue
        field = None if body.startswith((" ", "\t")) else _DEB822_FIELD.match(body)
        if field:
            in_uris = field.group(1).lower() == "uris"
            if in_uris:
                value, hit = _rewrite_uris(field.group(2))
                changed |= hit
                body = f"{field.group(1)}:{value}"
        elif in_uris and body[:1] in (" ", "\t") and body.strip() != ".":
            value, hit = _rewrite_uris(body)
            changed |= hit
            body = value
        out.append(body + ending)
    return out, changed


def rewrite_deb822(text):
    out, changed = [], False
    stanza = []
    for line in text.splitlines(keepends=True):
        if not line.strip():
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
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        if body.lstrip().startswith("#"):
            out.append(body + ending)
            continue
        match = _ONE_LINE.match(body)
        if match:
            _check_one_line_options(match.group("opts"))
            if is_mirror(match.group("uri")):
                body = match.group("head") + CANONICAL + match.group("tail")
                changed = True
        out.append(body + ending)
    return "".join(out), changed


def rewrite(text, deb822):
    """Return (rewritten text, changed). Refuses active entries disabling signatures."""
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
        text, changed = rewrite(source.read_text(), deb822)
    except (OSError, UnicodeDecodeError, ValueError) as error:
        print(f"cannot rewrite {source}: {error}", file=sys.stderr)
        return 2
    if not changed:
        print(f"{source} names no regional Ubuntu archive mirror", file=sys.stderr)
        return 3
    dest.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
