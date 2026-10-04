"""Deterministic publisher: approved bytes and exact PR binding, no model/tools."""

import importlib.util
from io import BytesIO
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

spec = importlib.util.spec_from_file_location("llm_review_io", Path(__file__).with_name("llm_review_io.py"))
io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(io)

FILES = {"input.json": io.INPUT_LIMIT, "review.txt": io.OUTPUT_LIMIT,
         "comment.txt": io.COMMENT_LIMIT, "manifest.json": 4096}


def download_artifact(artifact_id):
    url = f"https://api.github.com/repos/{io.REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(url, headers=io.github_headers())
    opener = urllib.request.build_opener(io.NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=120):
            raise ValueError("expected an immutable artifact download redirect")
    except urllib.error.HTTPError as error:
        io.require(error.code == 302, "artifact download was refused")
        location = error.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    io.require(parsed.scheme == "https" and parsed.hostname
               and not parsed.username and not parsed.password, "unsafe artifact redirect")
    # This URL comes from GitHub, not the artifact/model. Follow once without
    # ANY credential; a second redirect is refused by request_bytes.
    return io.request_bytes(location, {}, limit=1_000_000)


def read_bundle(archive):
    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        io.require(len(entries) == len(FILES)
                   and {entry.filename for entry in entries} == set(FILES),
                   "unexpected or duplicate archive members")
        result = {}
        for entry in entries:
            mode = (entry.external_attr >> 16) & 0o170000
            io.require(not entry.is_dir() and mode in (0, 0o100000)
                       and 0 < entry.file_size <= FILES[entry.filename],
                       "unsafe or oversized archive member")
            with bundle.open(entry) as member:
                data = member.read(FILES[entry.filename] + 1)
            io.require(len(data) == entry.file_size, "archive size mismatch")
            result[entry.filename] = data
        return result


def validate_run(run, run_id, trusted_sha):
    io.require(type(run.get("id")) is int and run["id"] == run_id, "wrong model run")
    io.require(run.get("path") == ".github/workflows/claude-review.yml"
               and run.get("event") == "workflow_dispatch"
               and run.get("head_branch") == "main"
               and run.get("head_sha") == trusted_sha
               and run.get("repository", {}).get("full_name") == io.REPOSITORY
               and run.get("head_repository", {}).get("full_name") == io.REPOSITORY,
               "untrusted model workflow identity")
    io.require(run.get("status") == "completed" and run.get("conclusion") == "success"
               and type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
               "model run must have one completed successful attempt")


def validate_bundle(bundle, *, pr_number, head, run_id, trusted_sha, hashes):
    manifest = io.load_json(bundle["manifest.json"])
    expected = {"schema", "repository", "pr", "head", "base", "run_id", "run_attempt",
                "trusted_sha", "input_sha256", "output_sha256", "comment_sha256"}
    io.require(isinstance(manifest, dict) and set(manifest) == expected, "bad manifest schema")
    for key, value in {"schema": 1, "repository": io.REPOSITORY, "pr": pr_number,
                       "head": head, "run_id": run_id, "run_attempt": 1,
                       "trusted_sha": trusted_sha}.items():
        io.require(type(manifest[key]) is type(value) and manifest[key] == value,
                   "manifest binding mismatch")
    base = io.hex_value(manifest["base"], 40)
    for field, filename in (("input_sha256", "input.json"), ("output_sha256", "review.txt"),
                            ("comment_sha256", "comment.txt")):
        io.require(manifest[field] == hashes[field] == io.digest(bundle[filename]),
                   "artifact differs from human-inspected digest")
    data = io.load_json(bundle["input.json"])
    io.require(isinstance(data, dict)
               and set(data) == {"schema", "repository", "pr", "head", "base", "patches"},
               "bad input schema")
    for key in ("schema", "repository", "pr", "head", "base"):
        io.require(type(data[key]) is type(manifest[key]) and data[key] == manifest[key],
                   "reviewed input binding mismatch")
    review = bundle["review.txt"].decode("utf-8")
    comment = io.render_comment(review, pr_number, head, hashes["input_sha256"], run_id)
    io.require(comment == bundle["comment.txt"], "rendered comment mismatch")
    return base, comment


def require_approval(history, actor):
    io.require(isinstance(history, list) and history, "no actual human environment approval")
    approvals = []
    for record in history:
        io.require(isinstance(record, dict), "malformed approval record")
        environments = record.get("environments")
        io.require(isinstance(environments, list), "missing approval environment")
        matching = [env for env in environments if isinstance(env, dict)
                    and env.get("name") == io.ENVIRONMENT]
        if not matching:
            continue
        io.require(record.get("state") == "approved", "environment approval was rejected")
        io.require(len(matching) == 1 and type(matching[0].get("id")) is int
                   and matching[0]["id"] > 0, "malformed environment identity")
        user = record.get("user", {})
        io.require(user.get("type") == "User" and user.get("login") == io.APPROVER
                   and type(user.get("id")) is int and user["id"] == 31913027
                   and user["login"].casefold() != actor.casefold(),
                   "approval must be from the independent named human")
        approvals.append(record)
    io.require(len(approvals) == 1, "ambiguous or missing human approval")


def prepare(api=io.github_api, download=download_artifact):
    trusted_sha = io.trusted_context()
    run_id = io.number(os.environ.get("REVIEW_RUN_ID"))
    pr_number = io.number(os.environ.get("REVIEW_PR"))
    head = io.hex_value(os.environ.get("REVIEW_HEAD"), 40)
    hashes = {name: io.hex_value(os.environ.get(variable), 64) for name, variable in (
        ("input_sha256", "REVIEW_INPUT_SHA256"), ("output_sha256", "REVIEW_OUTPUT_SHA256"),
        ("comment_sha256", "REVIEW_COMMENT_SHA256"),
    )}
    run_path = f"repos/{io.REPOSITORY}/actions/runs/{run_id}"
    validate_run(api(run_path), run_id, trusted_sha)
    artifacts = api(f"{run_path}/artifacts?per_page=100")
    io.require(artifacts.get("total_count") == 1 and len(artifacts.get("artifacts", [])) == 1,
               "missing or ambiguous model artifact")
    artifact = artifacts["artifacts"][0]
    io.require(artifact.get("name") == f"llm-review-{run_id}-1"
               and artifact.get("expired") is False, "wrong or expired model artifact")
    artifact_id = io.number(str(artifact.get("id")))
    bundle = read_bundle(download(artifact_id))
    base, comment = validate_bundle(bundle, pr_number=pr_number, head=head, run_id=run_id,
                                    trusted_sha=trusted_sha, hashes=hashes)
    io.validate_pr(api(f"repos/{io.REPOSITORY}/pulls/{pr_number}"), pr_number, head, base)
    # Recheck after downloading: a newly initiated rerun invalidates the bundle.
    validate_run(api(run_path), run_id, trusted_sha)
    return pr_number, head, base, comment, hashes


def publish(prepared, api=io.github_api):
    pr_number, head, base, comment, hashes = prepared
    run_id = io.number(os.environ.get("GITHUB_RUN_ID"))
    actor = os.environ.get("GITHUB_ACTOR")
    io.require(isinstance(actor, str) and actor, "missing publisher actor")
    require_approval(api(f"repos/{io.REPOSITORY}/actions/runs/{run_id}/approvals"), actor)
    # Serialize dispatches by PR in the workflow and make a repeated authorized
    # dispatch a no-op. Do not update existing comments or retry uncertain POSTs.
    for page in range(1, 21):
        comments = api(f"repos/{io.REPOSITORY}/issues/{pr_number}/comments?per_page=100&page={page}")
        io.require(isinstance(comments, list), "malformed comment list")
        for existing in comments:
            if (existing.get("user", {}).get("login") == "github-actions[bot]"
                    and existing.get("body") == comment.decode("utf-8")):
                return
        if len(comments) < 100:
            break
    else:
        raise ValueError("comment history exceeds the safe pagination limit")
    # This is the last read before the sole write; head changes during the
    # unavoidable read/write race remain visible in the exact-SHA comment.
    io.validate_pr(api(f"repos/{io.REPOSITORY}/pulls/{pr_number}"), pr_number, head, base)
    api(f"repos/{io.REPOSITORY}/issues/{pr_number}/comments",
        payload={"body": comment.decode("utf-8")})


def main():
    io.require(len(sys.argv) == 2 and sys.argv[1] in ("inspect", "publish"), "invalid mode")
    prepared = prepare()
    if sys.argv[1] == "publish":
        publish(prepared)
        print("Published the single human-approved comment on the bound pull request.")
    else:
        pr_number, head, base, comment, hashes = prepared
        summary = (f"Review target: PR #{pr_number}, head `{head}`, base `{base}`.\n\n"
                   + "\n".join(f"{name}: `{value}`" for name, value in hashes.items())
                   + "\n\nInspect all four source artifact files, especially comment.txt, "
                   "before approving llm-review-publication. No model text is rendered here.\n")
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as handle:
            handle.write(summary)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, zipfile.BadZipFile):
        print("Review publication refused; do not retry a write with uncertain status.", file=sys.stderr)
        sys.exit(1)
