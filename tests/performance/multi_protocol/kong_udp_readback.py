"""Data-only ledger for the hosted fixture's fixed Kong provenance queries.

No subprocesses, config execution, include following, or effective-value guesses.
The shell owns literal commands and their deadlines; this reader bounds storage.
"""

import hashlib
import json
import re
import sys
import time
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
COMMAND_LIMIT = 256 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024
INCLUDE_LIMIT = 128
INCLUDE_OPERAND_LIMIT = 1024
CONFIGS = (
    "/usr/local/kong/nginx.conf",
    "/usr/local/kong/nginx-inject.conf",
    "/usr/local/kong/nginx-kong.conf",
    "/usr/local/kong/nginx-kong-inject.conf",
    "/usr/local/kong/nginx-kong-gui-include.conf",
    "/usr/local/kong/nginx-kong-stream.conf",
    "/usr/local/kong/nginx-kong-stream-inject.conf",
)
SOURCES = (
    "/usr/local/share/lua/5.1/kong/templates/nginx.lua",
    "/usr/local/share/lua/5.1/kong/templates/nginx_kong_stream.lua",
    "/usr/local/share/lua/5.1/kong/templates/nginx_kong_stream_inject.lua",
    "/usr/local/share/lua/5.1/kong/templates/kong_defaults.lua",
    "/usr/local/share/lua/5.1/kong/init.lua",
    "/usr/local/share/lua/5.1/kong/runloop/handler.lua",
    "/usr/local/share/lua/5.1/kong/runloop/balancer/init.lua",
    "/usr/local/openresty/lualib/ngx/balancer.lua",
)
QUERIES = ("container", "image", "kong-version", "nginx-version", "package-version",
           "package-files", "nginx-hash")
KEYS = QUERIES + CONFIGS + SOURCES


_CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_NGINX_INCLUDE_RE = re.compile(r"\binclude\s+([^;\n{}]+);")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stem(key):
    # Artifact names never come from config contents, container output or paths.
    return f"{KEYS.index(key):02d}"


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def begin(directory, cid, image):
    if not _CONTAINER_ID_RE.fullmatch(cid) or not _IMAGE_ID_RE.fullmatch(image):
        raise ValueError("full fixture container and pinned image IDs required")
    directory.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name in ("kong_udp_readback.sh", "kong_udp_readback.py", "run_gateway_protocol_bench.sh",
                 "udp_profile_manifest.json", "configs/kong/udp.yaml"):
        sources[name] = digest((ROOT / name).read_bytes())
    save(directory / "manifest.json", dict(schema=1, container_id=cid, image_id=image,
         started_unix_secs=time.time(), source_sha256=sources, commands=list(KEYS),
         per_command_bytes=COMMAND_LIMIT, aggregate_bytes=TOTAL_LIMIT,
         stream="combined stdout/stderr; hashes of retained prefixes when truncated",
         session_comparability_complete=False, effective_values=None))


def capture(directory, key, stream):
    name = stem(key)
    # Fixed inventory, no directory traversal or recursive discovery.
    used = sum((directory / f"{stem(item)}.raw").stat().st_size for item in KEYS
               if (directory / f"{stem(item)}.raw").exists())
    limit = min(COMMAND_LIMIT, max(0, TOTAL_LIMIT - used))
    metadata = directory / f"{name}.json"
    row = dict(key=key, unix_secs=time.time(), limit_bytes=limit,
               truncated=None, aggregate_limited=limit < COMMAND_LIMIT,
               command_status=None, reader_status=None)
    save(metadata, row)
    observed, retained = 0, 0
    hasher = hashlib.sha256()
    read = getattr(stream, "read1", stream.read)
    try:
        with (directory / f"{name}.raw").open("wb") as output:
            while True:
                chunk = read(min(65536, limit + 1 - observed))
                if not chunk:
                    row["truncated"] = False
                    break
                observed += len(chunk)
                prefix = chunk[:max(0, limit - retained)]
                output.write(prefix)
                output.flush()  # Preserve partial output even if the job is canceled.
                retained += len(prefix)
                hasher.update(prefix)
                if observed > limit:
                    row["truncated"] = True
                    break
    except OSError as error:
        row["error"] = type(error).__name__
        raise
    finally:
        row.update(retained_bytes=retained, observed_bytes_at_least=observed,
                   sha256=hasher.hexdigest())
        save(metadata, row)
    # Close the pipe at the cap. A producer SIGPIPE is preserved alongside
    # truncation; no attempt is made to drain unbounded output into memory/disk.


def status(directory, key, command_status, reader_status):
    path = directory / f"{stem(key)}.json"
    if path.exists():
        row = json.loads(path.read_text())
    else:
        row = dict(key=key, error="reader did not produce metadata")
    row.update(command_status=int(command_status), reader_status=int(reader_status))
    save(path, row)


def read_record(directory, key):
    try:
        row = json.loads((directory / f"{stem(key)}.json").read_text())
        if not isinstance(row, dict):
            raise ValueError("command metadata must be an object")
        raw = (directory / f"{stem(key)}.raw").read_bytes()
        row["complete"] = (row.get("command_status") == 0 and row.get("reader_status") == 0
                           and row.get("truncated") is False and row.get("sha256") == digest(raw))
    except (OSError, ValueError):
        return dict(key=key, complete=False, error="missing/malformed capture"), b""
    if key in CONFIGS + SOURCES:
        header, separator, body = raw.partition(b"\n")
        expected = re.fullmatch(rb"([0-9a-f]{64})  " + re.escape(key.encode()), header)
        row["source_sha256"] = expected[1].decode() if expected else None
        row["content_sha256"] = digest(body)
        row["complete"] = bool(row["complete"] and separator and expected
                               and row["source_sha256"] == digest(body))
        if not row["complete"]:
            row["source_verified"] = False
            row["source_error"] = "incomplete capture or source hash/header mismatch"
        else:
            row["source_verified"] = True
        return row, body
    return row, raw


def identity(directory):
    manifest = json.loads((directory / "manifest.json").read_text())
    row, raw = read_record(directory, "container")
    try:
        observed = json.loads(raw)
        return (row["complete"] and observed["id"] == manifest["container_id"]
                and observed["image"] == manifest["image_id"] and observed["running"] is True)
    except (ValueError, KeyError, TypeError):
        return False


def include_candidates(contents):
    """Conservative review index, NOT an NGINX/Lua parser or inheritance engine.

    Unknown paths/globs are evidence gaps, never file-open instructions. Raw
    config is authoritative: inline Lua, quoting and vendor syntax need review.
    """
    edges, truncated = [], False
    for source, raw in contents.items():
        text = raw.decode("utf-8", "replace")
        for match in _NGINX_INCLUDE_RE.finditer(text):
            if len(edges) == INCLUDE_LIMIT:
                return edges, True
            operand = match[1].strip().strip("\"'")
            operand_truncated = len(operand) > INCLUDE_OPERAND_LIMIT
            truncated |= operand_truncated
            operand = operand[:INCLUDE_OPERAND_LIMIT]
            target = str(PurePosixPath("/usr/local/kong") / operand)
            edges.append(dict(source=source, operand=operand, target=target,
                              captured=not operand_truncated and target in contents,
                              operand_truncated=operand_truncated,
                              line=text[:match.start()].count("\n") + 1))
    return edges, truncated


def finish(directory):
    records, contents = [], {}
    for key in KEYS:
        row, body = read_record(directory, key)
        records.append(row)
        if key in CONFIGS and row["complete"]:
            contents[key] = body
    edges, index_truncated = include_candidates(contents)
    result = dict(schema=1, finished_unix_secs=time.time(), identity_verified=identity(directory),
                  commands=records, all_commands_complete=all(row["complete"] for row in records),
                  include_candidates=edges, unresolved_includes=[e for e in edges if not e["captured"]],
                  include_index_truncated=index_truncated,
                  include_review="required; fixed allowlist only, no recursive reads or nginx -T",
                  session_comparability_complete=False, effective_values=None,
                  limitations=["client socket lifetime does not establish Kong session lifetime",
                               "review raw config inheritance and runtime Lua timeout paths",
                               "exact enterprise native patchset remains an external gap"])
    save(directory / "summary.json", result)
    return result


if __name__ == "__main__":
    command, folder, *args = sys.argv[1:]
    directory = Path(folder)
    if command == "begin":
        begin(directory, *args)
    elif command == "capture":
        capture(directory, args[0], sys.stdin.buffer)
    elif command == "status":
        status(directory, *args)
    elif command == "identity":
        sys.exit(0 if identity(directory) else 1)
    elif command == "finish":
        finish(directory)
    else:
        raise ValueError("unknown readback operation")
