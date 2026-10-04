"""Trusted transport and data validation; never execute reviewed content."""

import hashlib
import json
import math
import os
import re
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "ferrum-edge/ferrum-edge"
ENVIRONMENT = "llm-review-publication"
APPROVER = "jeremyjpj0916"
APPROVER_ID = 31913027
INPUT_LIMIT = 400_000
OUTPUT_LIMIT = 12_000
COMMENT_LIMIT = 60_000
API_LIMIT = 2_000_000
ARCHIVE_LIMIT = 1_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,14}", value),
            "missing or malformed positive number")
    return int(value)


def hex_value(value, length):
    require(isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value),
            "missing or malformed digest")
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":"))
            + "\n").encode("utf-8")


def load_json(data, *, limit=API_LIMIT):
    require(type(data) is bytes and 0 < len(data) <= limit, "invalid JSON byte length")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def finite(value):
        result = float(value)
        require(math.isfinite(result), "nonfinite JSON number")
        return result

    def refuse_constant(value):
        raise ValueError("nonfinite JSON constant")

    try:
        return json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=unique,
                          parse_constant=refuse_constant, parse_float=finite)
    except (UnicodeError, RecursionError):
        raise ValueError("invalid UTF-8 or excessive JSON nesting") from None


def text(value, limit, *, multiline=False):
    require(isinstance(value, str), "invalid text type")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ValueError("invalid Unicode text") from None
    require(0 < len(encoded) <= limit, "empty or oversized text")
    require(all(unicodedata.category(c)[0] != "C" or (multiline and c in "\n\t")
                for c in value), "invalid text control character")
    return value


def validate_input(data, pr_number, head, base):
    require(isinstance(data, dict)
            and set(data) == {"schema", "repository", "pr", "head", "base", "patches"},
            "bad input schema")
    for key, value in {"schema": 1, "repository": REPOSITORY, "pr": pr_number,
                       "head": head, "base": base}.items():
        require(type(data[key]) is type(value) and data[key] == value, "input binding mismatch")
    patches = data["patches"]
    require(isinstance(patches, list) and 0 < len(patches) < 300, "invalid patch count")
    paths = set()
    for item in patches:
        require(isinstance(item, dict) and set(item) == {"path", "status", "patch"},
                "bad patch schema")
        name = text(item["path"], 1024)
        require("\\" not in name and all(part not in ("", ".", "..") for part in name.split("/"))
                and name not in paths, "unsafe or duplicate patch path")
        paths.add(name)
        require(isinstance(item["status"], str) and item["status"] in
                {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"},
                "invalid patch status")
        text(item["patch"], INPUT_LIMIT, multiline=True)
    require(len(json_bytes(data)) <= INPUT_LIMIT, "patch input exceeds the data limit")
    return data


def safe_url(url, *, artifact=False):
    require(isinstance(url, str) and len(url) <= 16_384
            and all(32 < ord(c) < 127 for c in url), "invalid HTTP URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid HTTP URL") from None
    require(parsed.scheme == "https" and not parsed.username and not parsed.password
            and port in (None, 443) and not parsed.fragment, "unsafe HTTP URL")
    if artifact:
        # GitHub's production artifact storage only. Unknown backends require
        # a reviewed allowlist change; never accept arbitrary public/private hosts.
        require(bool(re.fullmatch(r"productionresultssa[0-9]+\.blob\.core\.windows\.net",
                                  parsed.hostname or "")), "unexpected artifact storage host")
    else:
        require((parsed.hostname == "api.github.com"
                 and parsed.path.startswith(f"/repos/{REPOSITORY}/"))
                or (parsed.hostname == "api.anthropic.com"
                    and parsed.path == "/v1/messages" and not parsed.query),
                "unexpected credentialed endpoint")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def request_bytes(url, headers, *, payload=None, limit=API_LIMIT):
    # Never forward credentials to redirects. Error output deliberately omits
    # response bodies, URLs, prompts, and request headers.
    safe_url(url, artifact=not headers)
    require(type(limit) is int and 0 < limit <= API_LIMIT, "invalid HTTP response limit")
    request = urllib.request.Request(url, headers=headers, data=payload)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=120) as response:
            result = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f"HTTP request refused with status {error.code}") from None
    except (urllib.error.URLError, OSError):
        raise ValueError("HTTP transport failed") from None
    require(len(result) <= limit, "HTTP response exceeds the data limit")
    return result


def github_headers():
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "GitHub token is missing")
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json"}


def github_api(path, *, payload=None):
    require(isinstance(path, str) and path.startswith(f"repos/{REPOSITORY}/")
            and re.fullmatch(r"[A-Za-z0-9_./?=&-]+", path)
            and all(part not in (".", "..") for part in path.split("/")),
            "unexpected GitHub repository or path")
    return load_json(request_bytes(f"https://api.github.com/{path}", github_headers(),
                                   payload=None if payload is None else json_bytes(payload)))


def trusted_context():
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "unexpected repository")
    require(os.environ.get("GITHUB_REF") == "refs/heads/main", "main is required")
    require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "manual dispatch is required")
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "reruns are not authorized")
    return hex_value(os.environ.get("GITHUB_SHA"), 40)


def validate_pr(pr, pr_number, head, base=None):
    require(isinstance(pr, dict) and isinstance(pr.get("head"), dict)
            and isinstance(pr.get("base"), dict) and isinstance(pr["base"].get("repo"), dict),
            "malformed pull request identity")
    require(type(pr.get("number")) is int and pr["number"] == pr_number,
            "wrong pull request number")
    require(pr.get("state") == "open", "pull request is not open")
    require(pr.get("head", {}).get("sha") == head, "pull request head changed")
    branch = pr.get("base", {})
    require(branch.get("repo", {}).get("full_name") == REPOSITORY
            and branch.get("ref") == "main", "wrong pull request base")
    resolved = hex_value(branch.get("sha"), 40)
    require(base is None or base == resolved, "pull request base changed")
    return resolved


def render_comment(review, pr_number, head, input_digest, run_id):
    require(isinstance(review, str) and 0 < len(review.encode("utf-8")) <= OUTPUT_LIMIT,
            "review output is empty or oversized")
    # Model text is literal code. Neutralize mentions, HTML and bidi/controls;
    # links cannot render as links inside this block.
    clean = "".join(c for c in review if c in "\n\t" or unicodedata.category(c)[0] != "C")
    clean = clean.replace("@", "＠").replace("<", "‹").replace(">", "›")
    require(bool(clean.strip()), "review contains no printable content")
    literal = "\n".join("    " + line.expandtabs(4) for line in clean.splitlines())
    body = (f"Human-approved automated review of PR #{pr_number} at `{head}`.\n\n"
            "The following is untrusted model output, independently inspected before publication.\n\n"
            f"Input SHA-256: `{input_digest}`; model run: `{run_id}`.\n\n{literal}\n")
    result = body.encode("utf-8")
    require(len(result) <= COMMENT_LIMIT, "rendered comment exceeds the data limit")
    return result
