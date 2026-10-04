"""Deterministic publisher: approved bytes and exact PR binding, no model/tools."""

import importlib.util
from io import BytesIO
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import zipfile

spec = importlib.util.spec_from_file_location("llm_review_io", Path(__file__).with_name("llm_review_io.py"))
io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(io)

FILES = {"input.json": io.INPUT_LIMIT, "review.txt": io.OUTPUT_LIMIT,
         "comment.txt": io.COMMENT_LIMIT, "manifest.json": 4096}


def download_artifact(artifact_id):
    io.require(type(artifact_id) is int and 0 < artifact_id < 10**15, "invalid artifact ID")
    url = f"https://api.github.com/repos/{io.REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(url, headers=io.github_headers())
    opener = urllib.request.build_opener(io.NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=120):
            raise ValueError("expected an immutable artifact download redirect")
    except urllib.error.HTTPError as error:
        io.require(error.code == 302, "artifact download was refused")
        location = error.headers.get("Location", "")
    except (urllib.error.URLError, OSError):
        raise ValueError("artifact HTTP transport failed") from None
    io.safe_url(location, artifact=True)
    # This URL comes from GitHub, not the artifact/model. Follow once without
    # ANY credential; a second redirect is refused by request_bytes.
    return io.request_bytes(location, {}, limit=io.ARCHIVE_LIMIT)


def read_bundle(archive):
    io.require(type(archive) is bytes and 0 < len(archive) <= io.ARCHIVE_LIMIT,
               "invalid archive byte length")
    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        io.require(len(entries) == len(FILES)
                   and {entry.filename for entry in entries} == set(FILES),
                   "unexpected or duplicate archive members")
        result = {}
        for entry in entries:
            mode = (entry.external_attr >> 16) & 0o170000
            io.require(not entry.is_dir() and mode in (0, 0o100000)
                       and not entry.flag_bits & 1
                       and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                       and 0 < entry.file_size <= FILES[entry.filename],
                       "unsafe or oversized archive member")
            with bundle.open(entry) as member:
                data = member.read(FILES[entry.filename] + 1)
            io.require(len(data) == entry.file_size, "archive size mismatch")
            result[entry.filename] = data
        return result


def validate_run(run, run_id, trusted_sha):
    io.require(isinstance(run, dict) and isinstance(run.get("repository"), dict)
               and isinstance(run.get("head_repository"), dict), "malformed model run")
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
    io.require(isinstance(bundle, dict) and set(bundle) == set(FILES)
               and all(type(data) is bytes and 0 < len(data) <= FILES[name]
                       for name, data in bundle.items()), "invalid bundle files or sizes")
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
    io.validate_input(io.load_json(bundle["input.json"], limit=io.INPUT_LIMIT),
                      pr_number, head, base)
    review = bundle["review.txt"].decode("utf-8")
    comment = io.render_comment(review, pr_number, head, hashes["input_sha256"], run_id)
    io.require(comment == bundle["comment.txt"], "rendered comment mismatch")
    return base, comment


def environment_settings(environment):
    io.require(isinstance(environment, dict) and environment.get("name") == io.ENVIRONMENT,
               "missing publication environment")
    identity = environment.get("id")
    io.require(type(identity) is int and identity > 0, "invalid environment ID")
    io.require(environment.get("can_admins_bypass") is False,
               "administrator bypass must be explicitly disabled")
    updated = environment.get("updated_at")
    io.require(isinstance(updated, str)
               and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", updated),
               "missing environment settings revision")
    policy = environment.get("deployment_branch_policy")
    io.require(isinstance(policy, dict)
               and set(policy) == {"protected_branches", "custom_branch_policies"}
               and policy["protected_branches"] is False
               and policy["custom_branch_policies"] is True, "custom main-only policy is required")
    rules = environment.get("protection_rules")
    io.require(isinstance(rules, list) and 2 <= len(rules) <= 3, "missing protection rules")
    admitted = {}
    for rule in rules:
        io.require(isinstance(rule, dict) and isinstance(rule.get("type"), str),
                   "malformed protection rule")
        kind = rule["type"]
        rule_id = rule.get("id")
        io.require(kind in {"required_reviewers", "branch_policy", "wait_timer"}
                   and kind not in admitted and type(rule_id) is int and rule_id > 0,
                   "unexpected or duplicate protection rule")
        admitted[kind] = {"id": rule_id}
        if kind == "required_reviewers":
            io.require(rule.get("prevent_self_review") is True, "prevent-self-review is required")
            reviewers = rule.get("reviewers")
            io.require(isinstance(reviewers, list) and len(reviewers) == 1,
                       "exactly the named human reviewer is required")
            reviewer = reviewers[0]
            io.require(isinstance(reviewer, dict) and reviewer.get("type") == "User"
                       and isinstance(reviewer.get("reviewer"), dict), "human reviewer is required")
            user = reviewer["reviewer"]
            io.require(user.get("type") == "User" and user.get("login") == io.APPROVER
                       and type(user.get("id")) is int and user["id"] == io.APPROVER_ID,
                       "wrong required human reviewer")
            admitted[kind].update(prevent_self_review=True, login=io.APPROVER, user_id=io.APPROVER_ID)
        elif kind == "wait_timer":
            io.require(type(rule.get("wait_timer")) is int and rule["wait_timer"] == 0,
                       "unexpected wait timer")
            admitted[kind]["wait_timer"] = 0
    io.require({"required_reviewers", "branch_policy"} <= set(admitted),
               "reviewer and branch protection are required")
    return {"id": identity, "name": io.ENVIRONMENT, "updated_at": updated,
            "can_admins_bypass": False, "deployment_branch_policy": policy,
            "protection_rules": admitted}


def protected_environment(api=io.github_api):
    path = f"repos/{io.REPOSITORY}/environments/{io.ENVIRONMENT}"
    first = environment_settings(api(path))
    policies = api(f"{path}/deployment-branch-policies?per_page=100")
    io.require(isinstance(policies, dict) and type(policies.get("total_count")) is int
               and policies["total_count"] == 1 and isinstance(policies.get("branch_policies"), list)
               and len(policies["branch_policies"]) == 1, "exactly one branch policy is required")
    branch = policies["branch_policies"][0]
    io.require(isinstance(branch, dict) and branch.get("name") == "main"
               and branch.get("type") == "branch" and type(branch.get("id")) is int
               and branch["id"] > 0, "only exact main branch deployments are permitted")
    # Refuse settings/identity motion during the separate policy read as well.
    io.require(first == environment_settings(api(path)), "environment changed during inspection")
    first["branch_policy"] = {"id": branch["id"], "name": "main", "type": "branch"}
    return first


def publisher_actor(api=io.github_api):
    trusted_sha = io.trusted_context()
    run_id = io.number(os.environ.get("GITHUB_RUN_ID"))
    actor = os.environ.get("GITHUB_ACTOR")
    io.require(isinstance(actor, str) and re.fullmatch(r"[A-Za-z0-9-]{1,39}", actor)
               and actor.casefold() != io.APPROVER.casefold(), "distinct human dispatch is required")
    run = api(f"repos/{io.REPOSITORY}/actions/runs/{run_id}")
    io.require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] == run_id
               and run.get("path") == ".github/workflows/llm-review-publish.yml"
               and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
               and run.get("head_sha") == trusted_sha
               and type(run.get("run_attempt")) is int and run["run_attempt"] == 1,
               "untrusted publisher workflow identity")
    user = run.get("actor")
    trigger = run.get("triggering_actor")
    io.require(isinstance(user, dict) and user.get("type") == "User" and user.get("login") == actor
               and type(user.get("id")) is int and user["id"] > 0 and user["id"] != io.APPROVER_ID
               and isinstance(trigger, dict) and trigger.get("type") == "User"
               and trigger.get("login") == actor and type(trigger.get("id")) is int
               and trigger["id"] == user["id"], "publisher initiator must be a distinct named human")
    return run_id, actor


def require_approval(history, actor, environment_id):
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
                   and matching[0]["id"] == environment_id, "approval environment identity changed")
        user = record.get("user", {})
        io.require(isinstance(user, dict) and user.get("type") == "User"
                   and user.get("login") == io.APPROVER
                   and type(user.get("id")) is int and user["id"] == io.APPROVER_ID
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
    io.require(isinstance(artifacts, dict) and type(artifacts.get("total_count")) is int
               and artifacts["total_count"] == 1 and isinstance(artifacts.get("artifacts"), list)
               and len(artifacts["artifacts"]) == 1,
               "missing or ambiguous model artifact")
    artifact = artifacts["artifacts"][0]
    io.require(isinstance(artifact, dict) and artifact.get("name") == f"llm-review-{run_id}-1"
               and artifact.get("expired") is False and type(artifact.get("id")) is int
               and 0 < artifact["id"] < 10**15 and type(artifact.get("size_in_bytes")) is int
               and 0 < artifact["size_in_bytes"] <= io.ARCHIVE_LIMIT,
               "wrong, expired or oversized model artifact")
    provenance = artifact.get("workflow_run")
    io.require(isinstance(provenance, dict) and type(provenance.get("id")) is int
               and provenance["id"] == run_id and provenance.get("head_sha") == trusted_sha
               and provenance.get("head_branch") == "main", "artifact source identity mismatch")
    artifact_id = artifact["id"]
    bundle = read_bundle(download(artifact_id))
    base, comment = validate_bundle(bundle, pr_number=pr_number, head=head, run_id=run_id,
                                    trusted_sha=trusted_sha, hashes=hashes)
    io.validate_pr(api(f"repos/{io.REPOSITORY}/pulls/{pr_number}"), pr_number, head, base)
    # Recheck after downloading: a newly initiated rerun invalidates the bundle.
    validate_run(api(run_path), run_id, trusted_sha)
    return pr_number, head, base, comment, hashes


def publish(prepared, api=io.github_api):
    pr_number, head, base, comment, hashes = prepared
    run_id, actor = publisher_actor(api)
    environment_id = io.number(os.environ.get("REVIEW_ENVIRONMENT_ID"))
    settings_digest = io.hex_value(os.environ.get("REVIEW_ENVIRONMENT_SHA256"), 64)

    def revalidate_environment():
        settings = protected_environment(api)
        io.require(settings["id"] == environment_id
                   and io.digest(io.json_bytes(settings)) == settings_digest,
                   "publication protection differs from the preapproval inspection")
        require_approval(api(f"repos/{io.REPOSITORY}/actions/runs/{run_id}/approvals"),
                         actor, environment_id)

    revalidate_environment()
    # Serialize dispatches by PR in the workflow and make a repeated authorized
    # dispatch a no-op. Do not update existing comments or retry uncertain POSTs.
    for page in range(1, 21):
        comments = api(f"repos/{io.REPOSITORY}/issues/{pr_number}/comments?per_page=100&page={page}")
        io.require(isinstance(comments, list), "malformed comment list")
        for existing in comments:
            io.require(isinstance(existing, dict) and isinstance(existing.get("user"), dict),
                       "malformed existing comment")
            if (existing["user"].get("login") == "github-actions[bot]"
                    and existing.get("body") == comment.decode("utf-8")):
                return
        if len(comments) < 100:
            break
    else:
        raise ValueError("comment history exceeds the safe pagination limit")
    # Revalidate the head and then the actual current protection/approval as
    # the last reads before the sole POST. Neither API offers an atomic POST
    # precondition; remaining head/settings races are documented, never retried.
    io.validate_pr(api(f"repos/{io.REPOSITORY}/pulls/{pr_number}"), pr_number, head, base)
    revalidate_environment()
    api(f"repos/{io.REPOSITORY}/issues/{pr_number}/comments",
        payload={"body": comment.decode("utf-8")})


def main():
    io.require(len(sys.argv) == 2 and sys.argv[1] in ("inspect", "publish"), "invalid mode")
    prepared = prepare()
    if sys.argv[1] == "publish":
        publish(prepared)
        print("Published the single human-approved comment on the bound pull request.")
    else:
        publisher_actor()
        settings = protected_environment()
        settings_digest = io.digest(io.json_bytes(settings))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"environment_id={settings['id']}\nenvironment_sha256={settings_digest}\n")
        pr_number, head, base, comment, hashes = prepared
        summary = (f"Review target: PR #{pr_number}, head `{head}`, base `{base}`.\n\n"
                   f"Protected environment ID: `{settings['id']}`; settings SHA-256: `{settings_digest}`.\n\n"
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
