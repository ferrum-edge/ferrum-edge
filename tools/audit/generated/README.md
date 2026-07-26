# Ferrum Edge static audit candidate report

- Audited SHA: `30dfc4aee3c16f5ea5ddcb7078a2b9da6f89564c`
- Files scanned: **1,524**
- Lines scanned: **1,381,059**
- Candidates: **35,768**
- Production candidates: **34,481**

These are review candidates, not automatically validated findings. Publication requires source-level verification and duplicate screening against the live open issue/PR backlog.

## Categories

- `performance`: 16561
- `correctness`: 5321
- `resource-exhaustion`: 3807
- `error-handling`: 2094
- `concurrency`: 2074
- `test-gap`: 2066
- `implementation-gap`: 1595
- `security`: 517
- `ci-integrity`: 413
- `lifecycle`: 315
- `memory-safety`: 234
- `durability`: 204
- `observability`: 156
- `supply-chain`: 124
- `filesystem-security`: 123
- `availability`: 71
- `configuration-security`: 37
- `operations`: 23
- `data-exposure`: 15
- `injection`: 13
- `container-security`: 4
- `database-performance`: 1

## Highest-volume rules

- `rust-to-vec`: 7699
- `rust-format-hot`: 4889
- `rust-prod-unwrap`: 4352
- `rust-map-full-scan`: 3312
- `rust-map-insert`: 3134
- `rust-ignore-test`: 2066
- `rust-relaxed-atomic`: 1548
- `rust-gap-language`: 1531
- `rust-let-underscore`: 873
- `rust-result-ok`: 643
- `rust-narrowing-cast`: 584
- `shell-error-suppression`: 408
- `rust-variable-capacity`: 366
- `rust-panic-macro`: 332
- `rust-unwrap-or-default`: 324
- `rust-detached-spawn`: 315
- `rust-full-sort`: 287
- `rust-blocking-fs`: 278
- `rust-json-materialize`: 265
- `rust-dangerous-tls`: 260
- `rust-if-let-ok`: 233
- `rust-unsafe-block`: 224
- `rust-file-write`: 204
- `rust-body-collect`: 181
- `rust-user-metric-label`: 156
- `rust-arc-swap-store`: 153
- `rust-unwrap-or-true`: 134
- `shell-unverified-download`: 124
- `rust-dynamic-path-join`: 123
- `rust-client-builder`: 71
- `rust-secret-equality`: 70
- `rust-todo-comment`: 64
- `rust-std-mutex`: 58
- `rust-read-to-string`: 45
- `rust-network-connect`: 41
- `rust-regex-compile`: 38
- `rust-serde-default-sensitive`: 37
- `rust-weak-hash`: 36
- `rust-string-lossy`: 31
- `rust-accept-loop`: 30
- `rust-spawn-blocking`: 26
- `rust-blocking-sleep`: 25
- `rust-read-to-end`: 24
- `yaml-missing-probe-marker`: 23
- `rust-unreachable-macro`: 22
- `rust-filter-map-ok`: 21
- `rust-log-secret`: 15
- `proto-unbounded-repeated`: 14
- `rust-blocking-command`: 12
- `proto-bytes-field`: 12
