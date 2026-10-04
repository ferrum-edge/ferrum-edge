"""Hosted-only qualification of the Compose candidate; never print credentials or logs."""

import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path


PG_IMAGE = (
    "postgres:16-alpine@sha256:"
    "721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
)
MONGO_IMAGE = (
    "mongo:7-jammy@sha256:"
    "f71f6d0913c945096cd058557cbadf4ad435007f378d84b3c4c636c928735e72"
)
EDGE_IMAGE = (
    "docker.io/ferrumedge/ferrum-edge:0.9.10@sha256:"
    "430d6a7d41361de5ad12562786481f97f1e97fef72a0b5f1a0699eced7cdd4cc"
)
PROJECT = "ferrum-fixture-qualification"
PG = "ferrum-test-pg-tls"
MYSQL = "ferrum-test-mysql-tls"
MYSQL_IMAGE = (
    "mysql:8.0@sha256:"
    "7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
)


class QualificationInterrupted(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def request(operation, **fields):
    return operation, fields


def command_env(command, env):
    operation, fields = command
    result = dict(os.environ if env is None else env)
    # Do not inherit operation/data selectors from the surrounding runner.
    for key in tuple(result):
        if key.startswith("FIXTURE_"):
            del result[key]
    result["FIXTURE_OPERATION"] = operation
    result.update({"FIXTURE_" + key.upper(): str(value) for key, value in fields.items()})
    return result


def run(command, *, env=None, timeout=30, check=True):
    try:
        result = subprocess.run(
            ["bash", "scripts/compose_fixture_command.sh"],
            env=command_env(command, env), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Fixture command exceeded its deadline") from None
    if check:
        require(result.returncode == 0, "Fixture command failed (output withheld)")
    return result


def inspect(name):
    return json.loads(run(request("inspect", container=name)).stdout)[0]


def mysql_failure(stderr):
    # Only a bounded numeric code and a fixed category may leave this function.
    # Retain neither the raw message nor SQLSTATE, user/host, paths or key bytes.
    if len(stderr) > 8192:
        return None, "oversized-diagnostic"
    lines = stderr.splitlines()
    errors = [line for line in lines if line.startswith("ERROR ")]
    if len(errors) != 1:
        return None, "missing-or-multiple-errors"
    if lines != errors:
        return None, "unexpected-diagnostic-lines"
    match = re.fullmatch(r"ERROR ([0-9]{4}) \(([A-Z0-9]{5})\): (.+)", errors[0])
    if match is None:
        return None, "unrecognized-error-header"
    code = int(match.group(1))
    sqlstate = match.group(2)
    message = match.group(3)
    if code == 2026 and message.startswith("SSL connection error: "):
        # The pinned OpenSSL 3 client uses ERR_error_string_n. Match its complete
        # library/reason record, not certificate words in arbitrary diagnostics.
        for tls_error, category in (
            ("error:0A000418:SSL routines::tlsv1 alert unknown ca", "tls-alert-unknown-ca"),
            ("error:0A000412:SSL routines::sslv3 alert bad certificate", "tls-alert-bad-certificate"),
            ("error:0A000416:SSL routines::sslv3 alert certificate unknown",
             "tls-alert-certificate-unknown"),
        ):
            if sqlstate == "HY000" and message == "SSL connection error: " + tls_error:
                return code, category
        return code, "tls-connection-error"
    if code == 1045 and message.startswith("Access denied for user "):
        return code, "authentication-rejected"
    if code == 3159 and message == (
        "Connections using insecure transport are prohibited while --require_secure_transport=ON."
    ):
        return code, "secure-transport-required"
    if code == 2013 and sqlstate == "HY000":
        # MySQL 8.0's published client catalog names CR_SERVER_LOST (2013) with
        # this fixed template. Keep the catalog label diagnostic-only.
        if message == "Lost connection to MySQL server during query":
            return code, "client-server-lost-during-query"
        late_read = re.fullmatch(
            r"Lost connection to MySQL server at 'reading "
            r"(?:authorization packet|final connect information)', system error: ([0-9]+)",
            message,
        )
        if late_read is not None:
            if late_read.group(1) == "0":
                return code, "late-auth-read-zero"
            if late_read.group(1) == "104":
                return code, "late-auth-read-connection-reset"
            return code, "late-auth-read-other-system-error"
        if message.startswith(
            "Lost connection to MySQL server at 'reading initial communication packet'"
        ):
            return code, "initial-handshake-read-disconnect"
    return code, "unclassified"


MYSQL_CERTIFICATE_ALERTS = (
    (2026, "tls-alert-unknown-ca"),
    (2026, "tls-alert-bad-certificate"),
    (2026, "tls-alert-certificate-unknown"),
)
# Authentication failures and late disconnects do not identify a certificate cause.
MYSQL_DEFAULT_REJECTIONS = MYSQL_CERTIFICATE_ALERTS


def check_mysql_classifier():
    late_read = (
        "ERROR 2013 (HY000): Lost connection to MySQL server at "
        "'reading authorization packet', system error: "
    )
    cases = (
        ("ERROR 2026 (HY000): SSL connection error: "
         "error:0A000418:SSL routines::tlsv1 alert unknown ca",
         (2026, "tls-alert-unknown-ca"), True),
        ("ERROR 2026 (HY000): SSL connection error: "
         "error:0A000412:SSL routines::sslv3 alert bad certificate",
         (2026, "tls-alert-bad-certificate"), True),
        ("ERROR 2026 (HY000): SSL connection error: "
         "error:0A000416:SSL routines::sslv3 alert certificate unknown",
         (2026, "tls-alert-certificate-unknown"), True),
        ("ERROR 2026 (HY000): SSL connection error: tlsv1 alert unknown ca",
         (2026, "tls-connection-error"), False),
        ("ERROR 2026 (HY000): SSL connection error: "
         "error:0A000418:SSL routines::tlsv1 alert unknown ca private-user",
         (2026, "tls-connection-error"), False),
        ("ERROR 2026 (HY001): SSL connection error: "
         "error:0A000418:SSL routines::tlsv1 alert unknown ca",
         (2026, "tls-connection-error"), False),
        ("ERROR 2026 (HY000): SSL connection error: "
         "error:0A000417:SSL routines::tlsv1 alert unknown ca",
         (2026, "tls-connection-error"), False),
        ("ERROR 1045 (28000): Access denied for user 'private-user'@'private-host'",
         (1045, "authentication-rejected"), False),
        (late_read + "0", (2013, "late-auth-read-zero"), False),
        (late_read.replace("authorization packet", "final connect information") + "0",
         (2013, "late-auth-read-zero"), False),
        (late_read + "104", (2013, "late-auth-read-connection-reset"), False),
        (late_read + "1", (2013, "late-auth-read-other-system-error"), False),
        (late_read + "0 trailing text", (2013, "unclassified"), False),
        (late_read.replace("HY000", "HY001") + "0", (2013, "unclassified"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server during query",
         (2013, "client-server-lost-during-query"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server during query private-user",
         (2013, "unclassified"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server during query /private/client.key",
         (2013, "unclassified"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server during query random-secret",
         (2013, "unclassified"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server during quer",
         (2013, "unclassified"), False),
        ("ERROR 2013 (HY000): Lost connection to MySQL server at "
         "'reading initial communication packet', system error: 0",
         (2013, "initial-handshake-read-disconnect"), False),
        ("ERROR 2026 (HY000): SSL connection error: unsupported protocol",
         (2026, "tls-connection-error"), False),
        ("ERROR 2026 (HY000): SSL connection error: Unable to get certificate /private/client.key",
         (2026, "tls-connection-error"), False),
        ("ERROR 2003 (HY000): Can't connect to MySQL server", (2003, "unclassified"), False),
        ("private stderr with no MySQL error", (None, "missing-or-multiple-errors"), False),
        ("unexpected output\nERROR 2026 (HY000): SSL connection error: "
         "error:0A000418:SSL routines::tlsv1 alert unknown ca",
         (None, "unexpected-diagnostic-lines"), False),
        (late_read + "0\n" + late_read + "0", (None, "missing-or-multiple-errors"), False),
        ("x" * 8193, (None, "oversized-diagnostic"), False),
    )
    for stderr, expected, accepted in cases:
        diagnostic = mysql_failure(stderr)
        require(diagnostic == expected, "MySQL diagnostic classification self-check failed")
        require((diagnostic in MYSQL_DEFAULT_REJECTIONS) == accepted,
                "MySQL diagnostic admission self-check failed")
    print("PASS: bounded MySQL diagnostics and fail-closed admission self-check", flush=True)


def refused(command, *, case, env=None, reasons=(), mysql_categories=None):
    # Case names are fixed literals, never commands, credentials or captured output.
    print("CHECK: negative control " + case, flush=True)
    try:
        result = run(command, env=env, check=False)
    except QualificationInterrupted:
        raise
    except RuntimeError:
        raise RuntimeError(case + ": negative control exceeded its deadline") from None
    require(result.returncode != 0, case + ": negative TLS/authentication control succeeded")
    diagnostic = None
    if command[0] == "mysql-query":
        diagnostic = mysql_failure(result.stderr)
        code, category = diagnostic
        print("DIAGNOSTIC: " + case + " mysql_error="
              + (str(code) if code is not None else "none") + " category=" + category, flush=True)
    accepted = (
        (result.returncode == 1 and not result.stdout and diagnostic in mysql_categories)
        if mysql_categories is not None
        else any(reason.lower() in result.stderr.lower() for reason in reasons)
    )
    require(
        accepted,
        case + ": negative control failed without the expected TLS/authentication diagnostic",
    )
    print("PASS: negative control " + case, flush=True)


def qualify_profiles(work):
    env = dict(os.environ)
    env.pop("MONGO_PASSWORD", None)
    env.pop("COMPOSE_PROFILES", None)
    for key in ("POSTGRES_PASSWORD", "FERRUM_ADMIN_JWT_SECRET", "FERRUM_CP_DP_GRPC_JWT_SECRET"):
        env[key] = secrets.token_hex(32)
    override = work / "published-images.json"
    override.write_text(json.dumps({
        "services": {
            name: {"image": image, "labels": {"org.ferrum.fixture.qualification": "true"}}
            for name, image in {
                "postgres": PG_IMAGE,
                "mongodb": MONGO_IMAGE,
                "ferrum-sqlite": EDGE_IMAGE,
                "ferrum-postgres": EDGE_IMAGE,
                "ferrum-mongodb": EDGE_IMAGE,
            }.items()
        }
    }))

    def compose(operation, check=True, timeout=180):
        return run(request(operation, override=override), env=env, check=check, timeout=timeout)

    def down():
        compose("compose-down")

    try:
        print("CHECK: default and PostgreSQL profile startup", flush=True)
        active = compose("compose-services").stdout.splitlines()
        require(set(active) == {"ferrum-sqlite", "postgres"}, "Unexpected default services")
        compose("compose-default-up")
        require(inspect("ferrum-sqlite")["State"]["Health"]["Status"] == "healthy",
                "Default SQLite profile failed")
        down()
        compose("compose-postgres-up")
        require(inspect("ferrum-postgres")["State"]["Health"]["Status"] == "healthy",
                "Non-Mongo PostgreSQL profile failed without MONGO_PASSWORD")
        down()

        # Interpolation still succeeds; the container boundary must reject startup.
        print("CHECK: Mongo secret rejection before initialization", flush=True)
        for value in (None, "", "a" * 31, "not-a-hexadecimal-password-value!!"):
            if value is None:
                env.pop("MONGO_PASSWORD", None)
            else:
                env["MONGO_PASSWORD"] = value
            compose("compose-config-check")
            result = compose("compose-mongo-invalid-up", check=False)
            require(result.returncode != 0, "Invalid Mongo secret produced a working profile")
            state = inspect("ferrum-mongodb-db")["State"]
            require(state["Status"] == "exited" and state["ExitCode"] == 1,
                    "Mongo secret guard did not fail before initialization")
            down()

        env["MONGO_PASSWORD"] = secrets.token_hex(32)
        print("CHECK: valid Mongo authentication with released Edge", flush=True)
        model = json.loads(compose("compose-config-json").stdout)
        uri = model["services"]["ferrum-mongodb"]["environment"]["FERRUM_DB_URL"]
        require(uri == "mongodb://ferrum:" + env["MONGO_PASSWORD"]
                + "@mongodb:27017/?authSource=admin", "Mongo URL/password contract differs")
        compose("compose-mongo-up")
        require(not inspect("ferrum-mongodb-db")["HostConfig"]["PortBindings"],
                "Mongo unexpectedly publishes a host port")
        require(inspect("ferrum-mongodb")["State"]["Health"]["Status"] == "healthy",
                "Released Edge did not connect using the valid Mongo credential")
        run(request("mongo-authenticated"))
        refused(
            request("mongo-historical-password"),
            case="mongo-historical-password", reasons=("authentication failed",),
        )
        # A valid initialized volume must not bypass either empty-input guard.
        for value in (None, ""):
            if value is None:
                env.pop("MONGO_PASSWORD", None)
            else:
                env["MONGO_PASSWORD"] = value
            result = compose("compose-mongo-recreate", check=False)
            require(result.returncode != 0, "Existing volume bypassed the missing/empty secret guard")
            state = inspect("ferrum-mongodb-db")["State"]
            require(state["Status"] == "exited" and state["ExitCode"] == 1,
                    "Existing Mongo volume served with a missing/empty secret")
        print("PASS: default/PostgreSQL profiles, Mongo guard, valid authentication and old-password refusal")
    finally:
        down()


def pg_args(connection, query="SELECT 1"):
    return request("pg-query", connection=connection, query=query)


def mysql_args(mode="trusted", query="SELECT 1"):
    return request("mysql-query", mysql_mode=mode, query=query)


def handshake_body(data, kind):
    if (len(data) < 4 or len(data) > 16384 or data[0] != kind
            or int.from_bytes(data[1:4], "big") != len(data) - 4):
        return None
    return data[4:]


def tls13_leaf(data):
    body = handshake_body(data, 11)
    # Initial TLS 1.3 Certificate messages have an empty request context.
    if (body is None or len(body) < 4 or body[0] != 0
            or int.from_bytes(body[1:4], "big") != len(body) - 4):
        return None
    offset, leaves = 4, []
    while offset < len(body):
        if len(leaves) == 4 or offset + 3 > len(body):
            return None
        size = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        if not 0 < size <= 8192 or offset + size + 2 > len(body):
            return None
        leaves.append(body[offset:offset + size])
        offset += size
        extensions = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2 + extensions
        if offset > len(body):
            return None
    return leaves[0] if leaves else None


TLS13_ROGUE_EVENTS = [
    "client-hello", "server-hello", "certificate-request", "server-certificate",
    "server-finished", "client-certificate", "client-signature", "client-finished",
    "unknown-ca",
]


def mysql_tls13_observer(server_der, client_der):
    evidence = {"socket": None, "events": [], "bytes": 0, "messages": 0,
                "ambiguous": False, "verified": False, "protocol": None, "connection": 0}

    def observe(connection, direction, version, content_type, kind, data):
        evidence["bytes"] += len(data)
        evidence["messages"] += 1
        if (connection is not evidence["socket"] or direction not in ("read", "write")
                or evidence["bytes"] > 65536 or evidence["messages"] > 128):
            evidence["ambiguous"] = True
        if evidence["ambiguous"]:
            return
        event = None
        if content_type == 21:  # Alert, decrypted by this connection's OpenSSL.
            if (direction == "read" and version == ssl.TLSVersion.TLSv1_3
                    and kind == 48 and data == b"\x02\x30"):
                event = "unknown-ca"
            else:
                evidence["ambiguous"] = True
        elif content_type == 22:  # Handshake, never application data.
            body = handshake_body(data, kind)
            if body is None:
                evidence["ambiguous"] = True
                return
            if kind in (1, 2):
                event = {("write", 1): "client-hello", ("read", 2): "server-hello"}.get(
                    (direction, kind)
                )
                evidence["ambiguous"] |= event is None
            elif kind in (11, 13, 15, 20):
                if version != ssl.TLSVersion.TLSv1_3:
                    evidence["ambiguous"] = True
                    return
                if kind == 13:
                    if (direction == "read" and len(body) >= 3 and body[0] == 0
                            and int.from_bytes(body[1:3], "big") == len(body) - 3):
                        event = "certificate-request"
                elif kind == 11:
                    expected = server_der if direction == "read" else client_der
                    if tls13_leaf(data) == expected:
                        event = "server-certificate" if direction == "read" else "client-certificate"
                elif kind == 15:
                    if direction == "read":
                        # The completed verified handshake validates the server signature.
                        return
                    # Generated client keys are RSA-2048; TLS 1.3 uses RSA-PSS.
                    if (len(body) == 260 and body[:2] in (b"\x08\x04", b"\x08\x05", b"\x08\x06")
                            and body[2:4] == b"\x01\x00" and any(body[4:])):
                        event = "client-signature"
                elif kind == 20 and len(body) in (32, 48):
                    event = "server-finished" if direction == "read" else "client-finished"
                evidence["ambiguous"] |= event is None
            elif kind != 8:  # Only EncryptedExtensions is unrecorded in this initial handshake.
                evidence["ambiguous"] = True
        if event is not None:
            evidence["events"].append(event)

    return evidence, observe


def bound_mysql_unknown_ca(evidence, error):
    return (
        not evidence["ambiguous"] and evidence["verified"]
        and evidence["protocol"] == "TLSv1.3" and 0 < evidence["connection"] <= 0xffffffff
        and evidence["events"] == TLS13_ROGUE_EVENTS
        and error.errno == ssl.SSL_ERROR_SSL and getattr(error, "library", None) == "SSL"
        and getattr(error, "reason", None) == "TLSV1_ALERT_UNKNOWN_CA"
    )


def check_mysql_tls13_parser():
    # Structural/adversarial self-checks only; these bytes are not a TLS fixture
    # or runtime rejection evidence. Only the live probe may report that evidence.
    leaf = b"parser-only"
    entry = len(leaf).to_bytes(3, "big") + leaf + b"\0\0"
    body = b"\0" + len(entry).to_bytes(3, "big") + entry
    message = b"\x0b" + len(body).to_bytes(3, "big") + body
    require(tls13_leaf(message) == leaf, "TLS certificate parser self-check failed")
    for malformed in (
        b"", message[:3], message[:-1], message + b"\0", b"\x0c" + message[1:],
        message[:4] + b"\x01" + message[5:],
        message[:5] + b"\xff\xff\xff" + message[8:],
        message[:8] + b"\0\0\0" + message[11:],
        message[:-2] + b"\xff\xff", b"x" * 16385,
    ):
        require(tls13_leaf(malformed) is None, "Malformed TLS certificate admitted")
    evidence, observe = mysql_tls13_observer(leaf, leaf)
    connection = object()
    evidence["socket"] = connection
    observe(connection, "read", ssl.TLSVersion.TLSv1_3, 21, 48, b"\x02\x30")
    error = ssl.SSLError(ssl.SSL_ERROR_SSL, "self-check only")
    error.library, error.reason = "SSL", "TLSV1_ALERT_UNKNOWN_CA"
    require(not bound_mysql_unknown_ca(evidence, error), "Unbound TLS alert admitted")
    for direction, version, kind, data in (
        ("write", ssl.TLSVersion.TLSv1_3, 48, b"\x02\x30"),
        ("read", ssl.TLSVersion.TLSv1_2, 48, b"\x02\x30"),
        ("read", ssl.TLSVersion.TLSv1_3, 42, b"\x02\x2a"),
        ("read", ssl.TLSVersion.TLSv1_3, 48, b"\x01\x30"),
        ("read", ssl.TLSVersion.TLSv1_3, 48, b"\x02\x30\0"),
    ):
        rejected, callback = mysql_tls13_observer(leaf, leaf)
        rejected["socket"] = connection
        callback(connection, direction, version, 21, kind, data)
        require(rejected["ambiguous"], "Nonmatching TLS alert admitted")
    for other, data in ((object(), message), (connection, b"x" * 65537)):
        rejected, callback = mysql_tls13_observer(leaf, leaf)
        rejected["socket"] = connection
        callback(other, "write", ssl.TLSVersion.TLSv1_3, 22, 11, data)
        require(rejected["ambiguous"], "Unbound or oversized TLS message admitted")
    rejected, callback = mysql_tls13_observer(leaf, b"different-certificate-signature")
    rejected["socket"] = connection
    callback(connection, "write", ssl.TLSVersion.TLSv1_3, 22, 11, message)
    require(rejected["ambiguous"], "Different TLS client certificate admitted")
    print("PASS: TLS parser negative self-checks; no runtime rejection evidence", flush=True)


def mysql_tls13_probe(certs):
    # A distinct no-authentication attempt, not instrumentation of the mysql CLI.
    # No SQL option file, password, auth response, query, transcript or key log.
    print("CHECK: separate MySQL default TLS 1.3 rogue-certificate handshake", flush=True)
    category = "unbound-tls-error"
    try:
        container = inspect(MYSQL)
        require(container["Config"]["Image"] == MYSQL_IMAGE, "Probe image differs")
        mounts = [item for item in container["Mounts"] if item["Destination"] == "/client"]
        require(len(mounts) == 1 and not mounts[0]["RW"]
                and mounts[0]["Source"] == str((certs / "client").resolve()),
                "Probe client material differs")
        paths = [certs / name for name in (
            "mysql/server.crt", "client/ca.crt", "client/rogue.crt", "client/rogue.key",
        )]
        require(all(path.stat().st_size <= 16384 for path in paths), "Probe material oversized")
        snapshot = [path.read_bytes() for path in paths]
        server_der = ssl.PEM_cert_to_DER_cert(snapshot[0].decode("ascii"))
        client_der = ssl.PEM_cert_to_DER_cert(snapshot[2].decode("ascii"))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
                "Probe server verification disabled")
        require(context.keylog_filename is None, "Probe key logging enabled")
        require(context.minimum_version == ssl.TLSVersion.TLSv1_2
                and context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
                and ssl.HAS_TLSv1_3,
                "Probe default protocol range differs")
        require(hasattr(type(context), "_msg_callback"), "Probe callback unavailable")
        context.load_verify_locations(cafile=paths[1])
        context.load_cert_chain(certfile=paths[2], keyfile=paths[3])
        evidence, context._msg_callback = mysql_tls13_observer(server_der, client_der)
        deadline = time.monotonic() + 5
        with socket.create_connection(("127.0.0.1", 13306), timeout=3) as raw:
            def remaining():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError
                return min(3, left)

            def receive(size):
                data = b""
                while len(data) < size:
                    raw.settimeout(remaining())
                    part = raw.recv(size - len(data))
                    require(part, "Probe initial disconnect")
                    data += part
                return data

            header = receive(4)
            size = int.from_bytes(header[:3], "little")
            require(header[3] == 0 and 21 <= size <= 4096, "Probe greeting differs")
            greeting = receive(size)
            end = greeting.find(b"\0", 1)
            require(greeting[0] == 10 and greeting[1:end] == b"8.0.46"
                    and end > 1 and end + 16 <= len(greeting), "Probe server differs")
            evidence["connection"] = int.from_bytes(greeting[end + 1:end + 5], "little")
            require(greeting[end + 13] == 0
                    and int.from_bytes(greeting[end + 14:end + 16], "little") & 0x800,
                    "Probe server lacks TLS")
            # MySQL SSLRequest, as used by OpenSSL's -starttls mysql; no auth payload.
            raw.settimeout(remaining())
            raw.sendall(b"\x20\x00\x00\x01\x85\xae\x7f\x00\x00\x00\x00\x01\x21" + bytes(23))
            with context.wrap_socket(raw, server_hostname="localhost",
                                     do_handshake_on_connect=False) as secure:
                evidence["socket"] = secure
                try:
                    secure.settimeout(remaining())
                    secure.do_handshake()
                    evidence["protocol"] = secure.version()
                    evidence["verified"] = secure.getpeercert(binary_form=True) == server_der
                    secure.settimeout(remaining())
                    data = secure.recv(1)
                    category = "unexpected-application-data" if data else "unexpected-eof"
                except ssl.SSLError as error:
                    if bound_mysql_unknown_ca(evidence, error):
                        category = "tls13-bound-unknown-ca"
        require(inspect(MYSQL)["Id"] == container["Id"], "Probe server replaced")
        require(snapshot == [path.read_bytes() for path in paths], "Probe material replaced")
    except TimeoutError:
        category = "timeout"
    except ssl.SSLError:
        category = "unbound-tls-error"
    except OSError:
        category = "network-or-material-failure"
    except QualificationInterrupted:
        raise
    except RuntimeError:
        category = "probe-capability-or-provenance-failure"
    # Even the certificate bytes/signatures and connection greeting stay in memory.
    proven = category == "tls13-bound-unknown-ca"
    numbers = (" tls_protocol=13 mysql_connection=" + str(evidence["connection"])
               + " tls_alert=48") if proven else ""
    print("DIAGNOSTIC: mysql-rogue-handshake-default category=" + category + numbers, flush=True)
    print(("PASS: " if proven else "UNQUALIFIED: ")
          + "separate MySQL default TLS 1.3 rogue-certificate handshake", flush=True)
    return proven


def assert_no_exposure(names, passwords):
    for name in names:
        container = inspect(name)
        surfaces = json.dumps(container["Config"]["Healthcheck"])
        surfaces += run(request("top", container=name)).stdout
        logs = run(request("logs", container=name))
        surfaces += logs.stdout
        # Logs can be emitted on either stream by the image entrypoint.
        surfaces += logs.stderr
        for password in passwords:
            require(password not in surfaces, "Credential found in healthcheck, process argv or logs")
        require(not any("PASSWORD=" in item or "MYSQL_PWD=" in item
                        for item in container["Config"]["Env"]),
                "Plaintext SQL password found in Docker environment configuration")
    # Include host Docker CLI argv, not only the SQL clients inside containers.
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            data = path.read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for password in passwords:
            require(password.encode() not in data, "Credential found in host process argv")


def qualify_sql(work):
    certs = work / "sql"
    setup = request("setup", certs_dir=certs)
    try:
        print("CHECK: generated SQL TLS fixtures and private files", flush=True)
        run(setup, timeout=180)
        passwords = [(certs / name).read_text().strip() for name in
                     ("pg-password", "mysql-password", "mysql-root-password")]
        for path in certs.rglob("*"):
            require(path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600),
                    "Private fixture file/directory permissions changed")
        # A rerun must not silently replace live databases or credentials.
        require(run(setup, check=False).returncode != 0,
                "Setup replaced an existing fixture")
        require(passwords == [(certs / name).read_text().strip() for name in
                             ("pg-password", "mysql-password", "mysql-root-password")],
                "Refused setup changed credentials")
        runner_ip = socket.gethostbyname(socket.gethostname())
        require(not runner_ip.startswith("127."), "Could not determine non-loopback runner address")
        for name, port, target in ((PG, 15432, "5432/tcp"), (MYSQL, 13306, "3306/tcp")):
            bindings = inspect(name)["NetworkSettings"]["Ports"][target]
            require(bindings == [{"HostIp": "127.0.0.1", "HostPort": str(port)}],
                    "SQL fixture is not published exclusively on IPv4 loopback")
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                pass
            try:
                with socket.create_connection((runner_ip, port), timeout=3):
                    raise RuntimeError("SQL fixture reachable through the runner network address")
            except OSError:
                pass

        pg_env = dict(os.environ, PGPASSWORD=passwords[0])
        connection = ("host=localhost user=ferrum dbname=ferrum connect_timeout=3 "
                      "sslmode=verify-full sslrootcert=/client/ca.crt "
                      "sslcert=/client/client.crt sslkey=/client/client.key")
        require(run(pg_args(connection), env=pg_env).stdout.strip() == "1", "PG SQL probe failed")
        require(run(mysql_args()).stdout.strip() == "1", "MySQL SQL probe failed")
        crud = ("CREATE DATABASE fixture_probe; CREATE TABLE fixture_probe.t (id INT); "
                "INSERT INTO fixture_probe.t VALUES (1); SELECT id FROM fixture_probe.t; "
                "DROP DATABASE fixture_probe;")
        require(run(mysql_args(query=crud)).stdout.strip() == "1", "MySQL create/drop grants failed")
        run(pg_args(connection, "CREATE DATABASE fixture_probe"), env=pg_env)
        run(pg_args(connection.replace("dbname=ferrum", "dbname=fixture_probe"),
                    "CREATE TABLE t (id INT); INSERT INTO t VALUES (1); SELECT id FROM t"), env=pg_env)
        run(pg_args(connection, "DROP DATABASE fixture_probe"), env=pg_env)

        # Wrong trust anchor and hostname controls share the successful query path.
        print("CHECK: verified SQL TLS and invalid trust/hostname controls", flush=True)
        run(request("untrusted-ca", certs_dir=certs))
        refused(pg_args(connection.replace("/client/ca.crt", "/client/bad-ca.crt")), env=pg_env,
                case="pg-wrong-ca", reasons=("certificate verify failed",))
        refused(pg_args(connection.replace("host=localhost", "host=wrong.invalid hostaddr=127.0.0.1")),
                env=pg_env, case="pg-wrong-hostname", reasons=("does not match host name",))
        refused(mysql_args("wrong-ca"), case="mysql-wrong-ca",
                reasons=("SSL connection error",))
        refused(mysql_args("wrong-hostname"), case="mysql-wrong-hostname",
                reasons=("SSL connection error",))
        refused(pg_args(connection.replace("sslmode=verify-full", "sslmode=disable")), env=pg_env,
                case="pg-plaintext", reasons=("pg_hba.conf rejects connection", "no pg_hba.conf entry"))
        refused(mysql_args("plaintext"), case="mysql-plaintext",
                reasons=("insecure transport", "secure transport",))

        # Require a client certificate after the ordinary verified TLS positives.
        print("CHECK: SQL mutual TLS positives and invalid client controls", flush=True)
        run(request("pg-require-client"))
        # The database reload is asynchronous; wait for explicit admission behaviour.
        no_client = pg_args(connection.replace("sslcert=/client/client.crt sslkey=/client/client.key",
                                               "sslcert='' sslkey=''"))
        deadline = time.monotonic() + 10
        while run(no_client, env=pg_env, check=False).returncode == 0:
            require(time.monotonic() < deadline, "PostgreSQL did not require client certificates")
            time.sleep(0.2)
        refused(no_client, env=pg_env, case="pg-missing-client",
                reasons=("valid client certificate", "certificate required"))
        ssl = run(pg_args(connection, "SELECT ssl, client_dn FROM pg_stat_ssl WHERE pid=pg_backend_pid()"),
                  env=pg_env).stdout.strip()
        require(ssl.startswith("t|") and "ferrum" in ssl, "PostgreSQL mTLS positive failed")
        run(request("mysql-require-client"))
        require(run(mysql_args()).stdout.strip() == "1", "MySQL mTLS positive failed")
        no_mysql_client = (certs / "mysql-client.cnf").read_text()
        no_mysql_client = "\n".join(line for line in no_mysql_client.splitlines()
                                    if not line.startswith(("ssl-cert=", "ssl-key="))) + "\n"
        (certs / "client/no-client.cnf").write_text(no_mysql_client)
        refused(mysql_args("no-client"), case="mysql-missing-client", reasons=("Access denied",))
        run(request("rogue-key", certs_dir=certs))
        (certs / "client/rogue.cnf").write_text("extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n")
        run(request("rogue-cert", certs_dir=certs))
        refused(pg_args(connection.replace("/client/client.crt", "/client/rogue.crt")
                        .replace("/client/client.key", "/client/rogue.key")), env=pg_env,
                case="pg-untrusted-client",
                reasons=("unknown ca", "certificate verify failed", "certificate unknown"))
        # Keep TLS 1.2 evidence separate from the default CLI and TLS 1.3 probe.
        # A late SQL/auth disconnect never establishes a certificate cause.
        require(run(mysql_args("trusted-tls12")).stdout.strip() == "1",
                "MySQL TLS 1.2 mTLS positive failed")
        refused(mysql_args("rogue-tls12"),
                case="mysql-untrusted-client-tls12",
                mysql_categories=MYSQL_CERTIFICATE_ALERTS)
        mysql_default_proven = False
        try:
            refused(mysql_args("rogue-default"), case="mysql-untrusted-client-default",
                    mysql_categories=MYSQL_DEFAULT_REJECTIONS)
            mysql_default_proven = True
        except QualificationInterrupted:
            raise
        except RuntimeError:
            # Collect the remaining controls/scans, then fail the whole qualification.
            # A separate handshake probe cannot relabel this exact CLI attempt.
            print("UNQUALIFIED: MySQL default CLI certificate rejection", flush=True)
        finally:
            # Prove availability after the wrong certificate even on an unidentified
            # rejection. A positive never converts that unresolved negative to PASS.
            require(run(mysql_args()).stdout.strip() == "1",
                    "MySQL default mTLS positive after untrusted-client rejection failed")
            print("PASS: MySQL default mTLS SELECT 1 after untrusted-client attempt", flush=True)

        mysql_tls13_proven = False
        try:
            protocol = run(mysql_args(query="SHOW SESSION STATUS LIKE 'Ssl_version'")).stdout.strip()
            if protocol == "Ssl_version\tTLSv1.3":
                mysql_tls13_proven = mysql_tls13_probe(certs)
            else:
                print("UNQUALIFIED: MySQL default CLI did not negotiate TLS 1.3", flush=True)
        finally:
            require(run(mysql_args()).stdout.strip() == "1",
                    "MySQL default mTLS positive after separate handshake probe failed")
            print("PASS: MySQL default mTLS SELECT 1 after separate handshake probe", flush=True)

        # Observe live, authenticated clients during a bounded query, then scan argv.
        print("CHECK: live SQL process argv, healthcheck configuration and logs", flush=True)
        processes = []
        try:
            for command, env in ((pg_args(connection, "SELECT pg_sleep(4)"), pg_env),
                              (mysql_args(query="SELECT SLEEP(4)"), None)):
                processes.append(subprocess.Popen(
                    ["bash", "scripts/compose_fixture_command.sh"],
                    env=command_env(command, env), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                ))
            deadline = time.monotonic() + 3
            while True:
                pg_top = run(request("top", container=PG)).stdout
                mysql_top = run(request("top", container=MYSQL)).stdout
                if "SELECT pg_sleep(4)" in pg_top and "SELECT SLEEP(4)" in mysql_top:
                    break
                require(time.monotonic() < deadline, "Did not observe live SQL probe processes")
                time.sleep(0.1)
            assert_no_exposure((PG, MYSQL), passwords)
            for process in processes:
                process.communicate(timeout=10)
                require(process.returncode == 0, "Live SQL probe failed")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
        print("PASS: live SQL argv, healthcheck and log credential scan", flush=True)
        require(mysql_tls13_proven, "Separate default TLS 1.3 probe lacks bound certificate evidence")
        require(mysql_default_proven,
                "Default MySQL CLI lacks certificate-specific evidence; separate probe is a distinct attempt")
        print("PASS: actual loopback bindings, private files, SQL CRUD, argv/log checks, TLS and mTLS controls")
    finally:
        if (certs / ".fixture-owned").exists():
            run(request("cleanup", certs_dir=certs), timeout=60)
        require(not certs.exists(), "SQL private fixture material remains after cleanup")


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true", "This qualification runs only on hosted Actions")
    check_mysql_classifier()
    check_mysql_tls13_parser()
    os.umask(0o077)
    work = Path(os.environ["RUNNER_TEMP"]) / "compose-fixture-qualification"
    work.mkdir(mode=0o700)
    qualify_profiles(work)
    qualify_sql(work)
    print("PASS: fixture qualification complete; no build or released-product certification performed")


def interrupted(*_):
    raise QualificationInterrupted("Qualification interrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except Exception as error:
        # Exception output can contain subprocess stderr; keep it out of hosted logs.
        message = str(error) if isinstance(error, RuntimeError) else "private command output withheld"
        print("FAIL: compose fixture qualification: " + message)
        raise SystemExit(1) from None
