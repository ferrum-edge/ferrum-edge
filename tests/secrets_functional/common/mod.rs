//! Shared scaffolding for the secret-backend functional tests.

pub mod env;

// Docker-backed fixtures (Vault dev server, LocalStack) — only compiled when a
// provider that needs them is enabled.
#[cfg(any(feature = "secrets-vault", feature = "secrets-aws"))]
pub mod containers;

// Host-port allocation for those fixtures, shared verbatim with the
// service-integration suite rather than reimplemented: Docker auto-assignment
// hands out a port from the host's ephemeral source-port range, which is the
// bind-drop-rebind hazard of issue #3999 and the reuse hazard that made this
// suite order-dependent (issue #5488). The allocator's own unit tests live in
// `tests/service_integration/host_port_allocation.rs`; a change to the module
// also schedules the Secret Backends job (see `SECRETS_BACKENDS_PATTERNS` in
// `.github/scripts/pr_ci_plan.py`).
#[cfg(any(feature = "secrets-vault", feature = "secrets-aws"))]
#[path = "../../service_integration/common/host_ports.rs"]
#[allow(dead_code)] // this suite needs one port per container, not the whole allocator API
pub mod host_ports;

// In-process wiremock fakes (GCP, Azure) — only compiled when a provider that
// needs them is enabled.
#[cfg(any(feature = "secrets-gcp", feature = "secrets-azure"))]
pub mod fakes;
