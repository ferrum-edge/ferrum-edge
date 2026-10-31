#!/usr/bin/env python3
import base64, hashlib, hmac, ipaddress, os, secrets, shlex, sys
from email.utils import formatdate
from urllib.parse import urlsplit

def default_port_for_scheme(scheme: str) -> int | None:
    if scheme in ("http", "ws"):
        return 80
    if scheme in ("https", "wss"):
        return 443
    return None

def is_valid_port(port: str) -> bool:
    return port.isascii() and port.isdigit() and 0 <= int(port) <= 65535

def _is_ascii_alnum(c: str) -> bool:
    return len(c) == 1 and c.isascii() and c.isalnum()

def is_valid_reg_name(host: str) -> bool:
    allowed = "-._%~!$&'()*+;="
    return host and all(_is_ascii_alnum(c) or c in allowed for c in host)

def is_valid_ip_literal_contents(content: str) -> bool:
    if not content:
        return False
    # Ferrum uses std::net::Ipv6Addr, which rejects zone identifiers.
    if "%" in content:
        return False
    try:
        ipaddress.IPv6Address(content)
        return True
    except ValueError:
        pass
    if content[0] in "vV":
        hex_part, _, addr = content[1:].partition(".")
        allowed = "-._~!$&'()*+,;=:"
        return (
            hex_part
            and all(c in "0123456789abcdefABCDEF" for c in hex_part)
            and addr
            and all(_is_ascii_alnum(c) or c in allowed for c in addr)
        )
    return False

def split_request_authority(value: str) -> tuple[str, str | None] | None:
    value = value.strip()
    if not value or "@" in value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or not is_valid_ip_literal_contents(value[1:end]):
            return None
        host = value[: end + 1]
        suffix = value[end + 1 :]
        if not suffix:
            return host, None
        if suffix.startswith(":") and is_valid_port(suffix[1:]):
            return host, suffix[1:]
        return None
    if ":" in value:
        host, port = value.rsplit(":", 1)
        if ":" in host:
            return None
        if is_valid_reg_name(host) and is_valid_port(port):
            return host, port
        return None
    if is_valid_reg_name(value):
        return value, None
    return None

def normalize_authority_host(host: str) -> str:
    if host.endswith("."):
        host = host[:-1]
    return host.lower()

def normalize_authority_for_signing(netloc: str, scheme: str) -> str:
    split = split_request_authority(netloc)
    if split is None:
        sys.exit("invalid URL authority for HMAC signing")
    host, port = split
    normalized_host = normalize_authority_host(host)
    default_port = default_port_for_scheme(scheme)
    if port is not None and default_port is not None and int(port) == default_port:
        return normalized_host
    if port is not None:
        return f"{normalized_host}:{port}"
    return normalized_host

def quote_auth_param(value: str) -> str:
    # HTTP quoted-string: escape backslash first, then the quote character.
    # The signing base keeps the raw value; only the wire auth-param is escaped.
    if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in value):
        sys.exit("username contains control characters that cannot appear in an HTTP header")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

secret = os.environ.get("HMAC_SECRET", "")
if sum(not char.isspace() for char in secret) < 32:
    sys.exit("set HMAC_SECRET to the Consumer hmac_auth secret (>= 32 non-whitespace chars)")

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/p/hmac"
username = sys.argv[2] if len(sys.argv) > 2 else "alice"
wire_username = quote_auth_param(username)  # validated before anything is signed
body = b'{"ping":1}'
namespace = os.environ.get("FERRUM_NAMESPACE", "ferrum")

parts = urlsplit(url)
scheme = parts.scheme.lower()
if scheme not in ("http", "https"):
    sys.exit(f"unsupported URL scheme for HMAC signing: {scheme or '(missing)'}")
if parts.username or parts.password or "@" in parts.netloc:
    sys.exit("URL userinfo is not permitted in HMAC authority")
if not parts.netloc:
    sys.exit("URL must include a host authority")
authority = normalize_authority_for_signing(parts.netloc, scheme)
path = parts.path or "/"
query = parts.query  # empty when absent; still a signing field
date = formatdate(usegmt=True)
nonce = secrets.token_hex(16)
digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
signing_string = "\n".join([
    "ferrum-hmac-v2",
    namespace,
    username,
    authority,
    "POST",
    path,
    query,
    date,
    digest,
    nonce,
])
signature = base64.b64encode(
    hmac.new(secret.encode(), signing_string.encode(), hashlib.sha256).digest()
).decode()
auth = (
    f'hmac username={wire_username}, algorithm="hmac-sha256", '
    f'nonce="{nonce}", signature="{signature}"'
)
cmd = [
    "curl", "-sS", "-D-", "-X", "POST", url,
    "-H", f"Authorization: {auth}",
    "-H", f"Date: {date}",
    "-H", f"Content-Digest: {digest}",
    "--data-binary", body.decode(),
]
print(" ".join(shlex.quote(part) for part in cmd))
