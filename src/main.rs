// Reuse gateway modules from the library without compiling CLI startup into it.
use ferrum_edge::*;

// Keep startup at the binary crate root, preserving its tracing target.
include!("gateway_entry.rs");

// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(all(not(windows), not(feature = "bench-h1-profile")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(not(windows), feature = "bench-h1-profile"))]
#[global_allocator]
static GLOBAL: h1_profile::ForwardingAllocator<tikv_jemallocator::Jemalloc> =
    h1_profile::ForwardingAllocator(tikv_jemallocator::Jemalloc);

fn main() {
    #[cfg(all(not(windows), feature = "bench-h1-profile"))]
    h1_profile::register_global_allocator();

    // Only the gateway process resolves an unconfigured managed-TLS store to
    // the documented `./ferrum-managed-tls`; library consumers such as the
    // test harnesses get a private per-process directory instead.
    config::env_config::use_working_directory_tls_managed_store_default();

    // SAFETY: this is the process entry point. No application worker or runtime
    // has started; the shared pipeline owns initialization and thread startup.
    unsafe {
        run_gateway_cli();
    }
}
