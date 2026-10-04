"""Trusted transport and data validation; never execute reviewed content."""

import hashlib
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request

REPOSITORY = "ferrum-edge/ferrum-edge"
ENVIRONMENT = "llm-review-publication"
APPROVER = "jeremyjpj0916"
INPUT_LIMIT = 400_000
OUTPUT_LIMIT = 12_000
COMMENT_LIMIT = 60_000
API_LIMIT = 2_000_000


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
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            + "\n").encode("utf-8")


def load_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def request_bytes(url, headers, *, payload=None, limit=API_LIMIT):
    # Never forward credentials to redirects. Error output deliberately omits
    # response bodies, URLs, prompts, and request headers.
    request = urllib.request.Request(url, headers=headers, data=payload)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=120) as response:
            result = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f"HTTP request refused with status {error.code}") from None
    except urllib.error.URLError:
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
    require(path.startswith(f"repos/{REPOSITORY}/"), "unexpected GitHub repository")
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
