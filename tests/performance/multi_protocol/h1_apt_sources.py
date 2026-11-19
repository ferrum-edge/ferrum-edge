"""Rewrite the runner's Ubuntu apt source to the canonical archive host.

Used only by ``h1_apt_install.sh`` when the hosted runner's regional mirror
(for example ``us-east-2.ec2.archive.ubuntu.com``) stalls or serves unusable
indexes. Only the mirror URI changes: every other field (``Types``,
``Suites``, ``Components``, ``Signed-By``, one-line ``[signed-by=...]``
options, comments) is kept byte for byte, so GPG verification is never
weakened and no unsigned repository is introduced. ``security.ubuntu.com``
and any non-Ubuntu URI (including third-party ``mirror+...`` lists) are left
as they are.

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
_MIRROR_URI = re.compile(
    r"^(?:https?://(?:[A-Za-z0-9-]+\.)+archive\.ubuntu\.com/ubuntu/?"
    r"|mirror(?:\+file)?:/+etc/apt/apt-mirrors\.txt"
    r"|mirror(?:\+https?)?://mirrors\.ubuntu\.com/[^\s]+)$"
)
_DEB822_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):(.*)$")
_ONE_LINE = re.compile(
    r"^(?P<head>\s*deb(?:-src)?\s+(?:(?P<opts>\[[^\]]*\])\s+)?)(?P<uri>\S+)(?P<tail>(?:\s.*)?)$"
)
_UNSAFE_FIELDS = frozenset({"trusted", "allow-insecure", "allow-weak"})
# APT's StringToBool truthy spellings (apt-pkg/contrib/strutl.cc).
_APT_TRUE = frozenset({"1", "yes", "true", "with", "on", "enable"})


def _is_apt_true(value):
    return value.strip().lower() in _APT_TRUE


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


def _check_deb822_unsafe(field_name, value):
    if field_name.lower() in _UNSAFE_FIELDS and _is_apt_true(value):
        raise ValueError(
            f"source sets {field_name}: {value.strip()}; refusing to rewrite unsafe source"
        )


def _check_one_line_options(opts_bracket):
    if not opts_bracket:
        return
    inner = opts_bracket[1:-1]
    for token in inner.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key.strip().lower() in _UNSAFE_FIELDS and _is_apt_true(value):
            raise ValueError(
                f"source sets [{key}={value}]; refusing to rewrite unsafe source"
            )


def rewrite_deb822(text):
    out, changed = [], False
    active_field = None
    active_unsafe_values = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        stripped = body.strip()
        if not stripped:
            if active_field and active_field.lower() in _UNSAFE_FIELDS:
                _check_deb822_unsafe(active_field, " ".join(active_unsafe_values))
            active_field = None
            active_unsafe_values = []
            out.append(body + ending)
            continue
        if body.startswith("#"):
            out.append(body + ending)
            continue
        field = None if body.startswith((" ", "\t")) else _DEB822_FIELD.match(body)
        if field:
            if active_field and active_field.lower() in _UNSAFE_FIELDS:
                _check_deb822_unsafe(active_field, " ".join(active_unsafe_values))
            active_field = field.group(1)
            active_unsafe_values = [field.group(2).strip()] if field.group(2).strip() else []
            if active_field.lower() == "uris":
                value, hit = _rewrite_uris(field.group(2))
                changed |= hit
                body = f"{field.group(1)}:{value}"
        elif active_field and body[:1] in (" ", "\t") and stripped != ".":
            if active_field.lower() == "uris":
                value, hit = _rewrite_uris(body)
                changed |= hit
                body = value
            elif active_field.lower() in _UNSAFE_FIELDS:
                active_unsafe_values.append(stripped)
        out.append(body + ending)
    if active_field and active_field.lower() in _UNSAFE_FIELDS:
        _check_deb822_unsafe(active_field, " ".join(active_unsafe_values))
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
