# Rust CodeQL extraction diagnostic

The default CodeQL Rust scan completes, but its initial run at
`00d94309caa774eee28409b5f9fef779e583ba14` reported macro-expansion,
unbuilt-procedural-macro, and missing `OUT_DIR` diagnostics. Its extractor
enabled all features, including the mutually exclusive `crypto-ring` and
`fips` profiles. Scanning every file does not establish complete macro or
generated-code coverage, and these diagnostics are not verified vulnerabilities.

After this workflow has landed on `main`, a maintainer can run:

```sh
gh workflow run codeql-extraction-diagnostic.yml --ref main
```

The workflow runs only on explicit dispatch in the public upstream repository,
on standard Ubuntu runners. The two jobs run sequentially, without a shared
build cache or artifact upload. CodeQL CLI 2.27.3 matches the initial baseline
and is pinned by its release asset's SHA-256 digest.

The ordinary profile selects `default,cloud-secrets`; the FIPS profile selects
`fips,cloud-secrets` without default features. Each installs the build-script
prerequisites and creates a database in build mode `none`, which lets the Rust
extractor build scripts and procedural macros without a full application build.
It does not evaluate queries, upload SARIF, replace default scanning, change
merge requirements, or establish FIPS certification.

Compare each job's complete extraction log, summary, and generated-binding
inventory. In particular, check Tokio `select!` expansion, SPIFFE Workload API
bindings, and the custom plugin registry. The raw WARN-line count is a
reproducible log measure, not a count of missing files or security alerts.
Warnings may repeat; absence of a warning does not prove complete modeling.
The binding inventory proves file existence only, not extraction of every path.

These two profiles are a diagnostic comparison. They do not cover every optional
feature or platform, and must not replace the current scans without a separate
coverage decision. Existing CodeQL baseline alerts still need independent
triage. This extraction-only workflow neither counts nor validates those alerts.
