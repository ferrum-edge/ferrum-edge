"""Hosted-only qualification of the Compose candidate; never print credentials or logs."""

import json
import os
import secrets
import signal
import socket
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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, *, env=None, timeout=30, check=True, input=None):
    try:
        result = subprocess.run(
            args, env=env, input=input, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Fixture command exceeded its deadline") from None
    if check:
        require(result.returncode == 0, "Fixture command failed (output withheld)")
    return result


def inspect(name):
    return json.loads(run(["docker", "inspect", name]).stdout)[0]


def refused(args, *, case, env=None, reasons):
    # Case names are fixed literals, never commands, credentials or captured output.
    print("CHECK: negative control " + case, flush=True)
    try:
        result = run(args, env=env, check=False)
    except RuntimeError:
        raise RuntimeError(case + ": negative control exceeded its deadline") from None
    require(result.returncode != 0, case + ": negative TLS/authentication control succeeded")
    require(
        any(reason.lower() in result.stderr.lower() for reason in reasons),
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
    base = [
        "docker", "compose", "--env-file", "/dev/null", "-p", PROJECT,
        "-f", "docker-compose.yml", "-f", str(override),
    ]

    def compose(*args, check=True, timeout=180):
        return run(base + list(args), env=env, check=check, timeout=timeout)

    def down():
        compose("--profile", "mongodb", "--profile", "postgres", "down", "--volumes")

    try:
        print("CHECK: default and PostgreSQL profile startup", flush=True)
        active = compose("config", "--services").stdout.splitlines()
        require(set(active) == {"ferrum-sqlite", "postgres"}, "Unexpected default services")
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "120")
        require(inspect("ferrum-sqlite")["State"]["Health"]["Status"] == "healthy",
                "Default SQLite profile failed")
        down()
        compose("--profile", "postgres", "up", "-d", "--no-build", "--wait",
                "--wait-timeout", "120", "ferrum-postgres")
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
            compose("--profile", "mongodb", "config", "--quiet")
            result = compose("--profile", "mongodb", "up", "-d", "--no-build", "--wait",
                             "--wait-timeout", "30", "mongodb", "ferrum-mongodb", check=False)
            require(result.returncode != 0, "Invalid Mongo secret produced a working profile")
            state = inspect("ferrum-mongodb-db")["State"]
            require(state["Status"] == "exited" and state["ExitCode"] == 1,
                    "Mongo secret guard did not fail before initialization")
            down()

        env["MONGO_PASSWORD"] = secrets.token_hex(32)
        print("CHECK: valid Mongo authentication with released Edge", flush=True)
        model = json.loads(compose("--profile", "mongodb", "config", "--format", "json").stdout)
        uri = model["services"]["ferrum-mongodb"]["environment"]["FERRUM_DB_URL"]
        require(uri == "mongodb://ferrum:" + env["MONGO_PASSWORD"]
                + "@mongodb:27017/?authSource=admin", "Mongo URL/password contract differs")
        compose("--profile", "mongodb", "up", "-d", "--no-build", "--wait",
                "--wait-timeout", "120", "mongodb", "ferrum-mongodb")
        require(not inspect("ferrum-mongodb-db")["HostConfig"]["PortBindings"],
                "Mongo unexpectedly publishes a host port")
        require(inspect("ferrum-mongodb")["State"]["Health"]["Status"] == "healthy",
                "Released Edge did not connect using the valid Mongo credential")
        auth = (
            "const c = new Mongo('mongodb://ferrum:' + "
            "process.env.MONGO_INITDB_ROOT_PASSWORD + '@localhost:27017/?authSource=admin');"
            "const s = c.getDB('admin').runCommand({connectionStatus:1});"
            "if (!s.ok || !s.authInfo.authenticatedUsers.some(u => u.user === 'ferrum')) quit(1);"
        )
        run(["docker", "exec", "ferrum-mongodb-db", "mongosh", "--quiet", "--nodb", "--eval", auth])
        refused(
            ["docker", "exec", "ferrum-mongodb-db", "mongosh", "--quiet", "--nodb", "--eval",
             "new Mongo('mongodb://ferrum:dev-password-change-in-production@localhost:27017/?authSource=admin')"],
            case="mongo-historical-password", reasons=("authentication failed",),
        )
        # A valid initialized volume must not bypass either empty-input guard.
        for value in (None, ""):
            if value is None:
                env.pop("MONGO_PASSWORD", None)
            else:
                env["MONGO_PASSWORD"] = value
            result = compose("--profile", "mongodb", "up", "-d", "--no-build", "--wait",
                             "--force-recreate", "--wait-timeout", "30", "mongodb",
                             "ferrum-mongodb", check=False)
            require(result.returncode != 0, "Existing volume bypassed the missing/empty secret guard")
            state = inspect("ferrum-mongodb-db")["State"]
            require(state["Status"] == "exited" and state["ExitCode"] == 1,
                    "Existing Mongo volume served with a missing/empty secret")
        print("PASS: default/PostgreSQL profiles, Mongo guard, valid authentication and old-password refusal")
    finally:
        down()


def pg_args(connection, query="SELECT 1"):
    return ["docker", "exec", "-e", "PGPASSWORD", PG, "psql", connection,
            "-v", "ON_ERROR_STOP=1", "-Atqc", query]


def mysql_args(*options, query="SELECT 1"):
    return ["docker", "exec", MYSQL, "mysql",
            "--defaults-extra-file=/run/secrets/mysql-client.cnf", "--batch",
            "--skip-column-names", *options, "-e", query]


def assert_no_exposure(names, passwords):
    for name in names:
        container = inspect(name)
        surfaces = json.dumps(container["Config"]["Healthcheck"])
        surfaces += run(["docker", "top", name, "-eo", "args"]).stdout
        logs = run(["docker", "logs", name])
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
    setup = ["bash", "tests/scripts/setup_db_tls.sh"]
    try:
        print("CHECK: generated SQL TLS fixtures and private files", flush=True)
        run(setup + [str(certs)], timeout=180)
        passwords = [(certs / name).read_text().strip() for name in
                     ("pg-password", "mysql-password", "mysql-root-password")]
        for path in certs.rglob("*"):
            require(path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600),
                    "Private fixture file/directory permissions changed")
        # A rerun must not silently replace live databases or credentials.
        require(run(setup + [str(certs)], check=False).returncode != 0,
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
        run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Untrusted Fixture CA", "-keyout", str(certs / "client/bad-ca.key"),
             "-out", str(certs / "client/bad-ca.crt")])
        refused(pg_args(connection.replace("/client/ca.crt", "/client/bad-ca.crt")), env=pg_env,
                case="pg-wrong-ca", reasons=("certificate verify failed",))
        refused(pg_args(connection.replace("host=localhost", "host=wrong.invalid hostaddr=127.0.0.1")),
                env=pg_env, case="pg-wrong-hostname", reasons=("does not match host name",))
        refused(mysql_args("--ssl-ca=/client/bad-ca.crt"), case="mysql-wrong-ca",
                reasons=("SSL connection error",))
        refused(mysql_args("--host=127.0.0.2"), case="mysql-wrong-hostname",
                reasons=("SSL connection error",))
        refused(pg_args(connection.replace("sslmode=verify-full", "sslmode=disable")), env=pg_env,
                case="pg-plaintext", reasons=("pg_hba.conf rejects connection", "no pg_hba.conf entry"))
        refused(mysql_args("--ssl-mode=DISABLED"), case="mysql-plaintext",
                reasons=("insecure transport", "secure transport",))

        # Require a client certificate after the ordinary verified TLS positives.
        print("CHECK: SQL mutual TLS positives and invalid client controls", flush=True)
        run(["docker", "exec", PG, "sh", "-ec",
             "sed -i 's/scram-sha-256$/scram-sha-256 clientcert=verify-full/' "
             "/var/lib/postgresql/tls/pg_hba.conf; "
             "psql -U ferrum -d ferrum -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()'"])
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
        run(["docker", "exec", MYSQL, "mysql", "--defaults-extra-file=/run/secrets/mysql-root.cnf",
             "-e", "ALTER USER 'ferrum'@'%' REQUIRE X509"])
        require(run(mysql_args()).stdout.strip() == "1", "MySQL mTLS positive failed")
        no_mysql_client = (certs / "mysql-client.cnf").read_text()
        no_mysql_client = "\n".join(line for line in no_mysql_client.splitlines()
                                    if not line.startswith(("ssl-cert=", "ssl-key="))) + "\n"
        (certs / "client/no-client.cnf").write_text(no_mysql_client)
        refused(["docker", "exec", MYSQL, "mysql", "--defaults-extra-file=/client/no-client.cnf",
                 "-e", "SELECT 1"], case="mysql-missing-client", reasons=("Access denied",))
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=ferrum",
             "-keyout", str(certs / "client/rogue.key"), "-out", str(certs / "client/rogue.csr")])
        (certs / "client/rogue.cnf").write_text("extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n")
        run(["openssl", "x509", "-req", "-days", "1", "-in", str(certs / "client/rogue.csr"),
             "-CA", str(certs / "client/bad-ca.crt"), "-CAkey", str(certs / "client/bad-ca.key"),
             "-CAcreateserial", "-extfile", str(certs / "client/rogue.cnf"),
             "-out", str(certs / "client/rogue.crt")])
        refused(pg_args(connection.replace("/client/client.crt", "/client/rogue.crt")
                        .replace("/client/client.key", "/client/rogue.key")), env=pg_env,
                case="pg-untrusted-client",
                reasons=("unknown ca", "certificate verify failed", "certificate unknown"))
        rogue_options = ("--ssl-cert=/client/rogue.crt", "--ssl-key=/client/rogue.key")
        # TLS 1.3 can finish SSL_connect before the server checks the client cert.
        # MySQL then masks the fatal alert as CR_SERVER_LOST while reading auth.
        # Require a certificate-specific TLS 1.2 alert from the same client/server
        # before allowing those exact late-disconnect messages on the default path.
        require(run(mysql_args("--tls-version=TLSv1.2")).stdout.strip() == "1",
                "MySQL TLS 1.2 mTLS positive failed")
        refused(mysql_args("--tls-version=TLSv1.2", *rogue_options),
                case="mysql-untrusted-client-tls12",
                reasons=("alert unknown ca", "alert bad certificate", "alert certificate unknown"))
        refused(mysql_args(*rogue_options), case="mysql-untrusted-client-default",
                reasons=(
                    "SSL connection error", "Access denied",
                    "ERROR 2013 (HY000): Lost connection to MySQL server at "
                    "'reading authorization packet', system error: 0",
                    "ERROR 2013 (HY000): Lost connection to MySQL server at "
                    "'reading final connect information', system error: 0",
                ))
        require(run(mysql_args()).stdout.strip() == "1",
                "MySQL default mTLS positive after untrusted-client rejection failed")

        # Observe live, authenticated clients during a bounded query, then scan argv.
        print("CHECK: live SQL process argv, healthcheck configuration and logs", flush=True)
        processes = []
        try:
            for args, env in ((pg_args(connection, "SELECT pg_sleep(4)"), pg_env),
                              (mysql_args(query="SELECT SLEEP(4)"), None)):
                processes.append(subprocess.Popen(args, env=env, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True))
            deadline = time.monotonic() + 3
            while True:
                pg_top = run(["docker", "top", PG, "-eo", "args"]).stdout
                mysql_top = run(["docker", "top", MYSQL, "-eo", "args"]).stdout
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
        print("PASS: actual loopback bindings, private files, SQL CRUD, argv/log checks, TLS and mTLS controls")
    finally:
        if (certs / ".fixture-owned").exists():
            run(setup + ["--cleanup", str(certs)], timeout=60)
        require(not certs.exists(), "SQL private fixture material remains after cleanup")


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true", "This qualification runs only on hosted Actions")
    os.umask(0o077)
    work = Path(os.environ["RUNNER_TEMP"]) / "compose-fixture-qualification"
    work.mkdir(mode=0o700)
    qualify_profiles(work)
    qualify_sql(work)
    print("PASS: fixture qualification complete; no build or released-product certification performed")


def interrupted(*_):
    raise RuntimeError("Qualification interrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except Exception as error:
        # Exception output can contain subprocess stderr; keep it out of hosted logs.
        message = str(error) if isinstance(error, RuntimeError) else "private command output withheld"
        print("FAIL: compose fixture qualification: " + message)
        raise SystemExit(1) from None
