exit=0
Settings (ferrum.conf): OK
  Mode: File
{"timestamp":"2026-08-20T08:02:26.787386Z","level":"INFO","fields":{"message":"Loading YAML configuration from /tmp/agent01-9xkfat51/readme.yaml"},"target":"ferrum_edge::config::file_loader"}
Spec (/tmp/agent01-9xkfat51/readme.yaml): OK
  Proxies: 1
  Consumers: 1
  Upstreams: 0
  Plugin configs: 1
Startup security (env TLS/CIDRs/metrics): OK

Validation passed.
{"timestamp":"2026-08-20T08:02:26.884508Z","level":"INFO","fields":{"message":"Configuration loaded (version 1): 1 proxies, 1 consumers, 1 plugin configs"},"target":"ferrum_edge::config::file_loader"}
{"timestamp":"2026-08-20T08:02:26.884657Z","level":"INFO","fields":{"message":"TLS policy: versions=[\"TLS 1.2\", \"TLS 1.3\"], cipher_suites=[\"TLS13_AES_128_GCM_SHA256\", \"TLS13_AES_256_GCM_SHA384\", \"TLS13_CHACHA20_POLY1305_SHA256\", \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\", \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\", \"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\", \"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256\", \"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\", \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\"], curves=[\"X25519\", \"secp256r1\"], prefer_server_order=true"},"target":"ferrum_edge::tls"}

{"timestamp":"2026-08-20T08:02:26.767075Z","level":"WARN","fields":{"message":"Config file /tmp/agent01-9xkfat51/readme.yaml is world-readable (mode 644). Consider restricting permissions as it may contain credentials."},"target":"ferrum_edge::config::file_loader"}

---spec---
version: "1"
proxies:
  - id: "my-api"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
    acl_groups:
      - "engineering"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
