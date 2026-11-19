"""Rewrite the runner's Ubuntu apt source to the canonical archive host.

Used only by ``h1_apt_install.sh`` when the hosted runner's regional mirror
(for example ``us-east-2.ec2.archive.ubuntu.com``) stalls or serves unusable
indexes. Only the mirror URI changes: every other field (``Types``,
``Suites``, ``Components``, ``Signed-By``, one-line ``[signed-by=...]``
options, comments) is kept byte for byte, so GPG verification is never
weakened and no unsigned repository is introduced. ``security.ubuntu.com``
and any non-Ubuntu URI are left as they are.

Usage: ``python3 h1_apt_sources.py SOURCE DEST``. Exit 0 after writing a
rewritten DEST, 3 when SOURCE names no regional Ubuntu mirror (DEST is not
written), 2 on usage or parse errors.
"""
import re
import sys
from pathlib import Path

CANONICAL = "http://archive.ubuntu.com/ubuntu/"

# Regional/cloud mirrors of the primary archive (``azure.``, ``us-east-2.ec2.``,
# ``<cc>.``) and apt mirror-list indirections the hosted images use.
_MIRROR_URI = re.compile(
    r"^(?:https?://(?:[A-Za-z0-9-]+\.)+archive\.ubuntu\.com/ubuntu/?"
    r"|mirror(?:\+[a-z]+)?:.+)$")
_DEB822_FIELD = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):(.*)$")
_ONE_LINE = re.compile(
    r"^(?P<head>\s*deb(?:-src)?\s+(?:\[[^\]]*\]\s+)?)(?P<uri>\S+)(?P<tail>(?:\s.*)?)$")
_UNSAFE = re.compile(r"(?im)^\s*(?:trusted|allow-insecure|allow-weak)\s*:\s*yes\b|\[[^\]]*\b(?:trusted|allow-insecure|allow-weak)=yes\b")


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


def rewrite_deb822(text):
    out, changed, in_uris = [], False, False
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        field = None if body.startswith((" ", "\t", "#")) else _DEB822_FIELD.match(body)
        if field:
            in_uris = field.group(1).lower() == "uris"
            if in_uris:
                value, hit = _rewrite_uris(field.group(2))
                changed |= hit
                body = f"{field.group(1)}:{value}"
        elif in_uris and body[:1] in (" ", "\t") and body.strip() and body.strip() != ".":
            value, hit = _rewrite_uris(body)
            changed |= hit
            body = value
        elif not body.strip():
            in_uris = False
        out.append(body + ending)
    return "".join(out), changed


def rewrite_one_line(text):
    out, changed = [], False
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body):]
        match = _ONE_LINE.match(body)
        if match and is_mirror(match.group("uri")):
            body = match.group("head") + CANONICAL + match.group("tail")
            changed = True
        out.append(body + ending)
    return "".join(out), changed


def rewrite(text, deb822):
    """Return (rewritten text, changed). Refuses sources that disable signatures."""
    if _UNSAFE.search(text):
        raise ValueError("source disables signature verification; refusing to rewrite it")
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
