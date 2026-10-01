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

/// Compile-time jemalloc options (issue #5588).
///
/// jemalloc's per-thread cache serves size classes up to `tcache_max` (32 KiB
/// by default). Each proxied request boxes its handler future, which is about
/// 90 KiB, so with the default every request allocates and frees through the
/// arena's extent path. Raising the cap to 128 KiB serves those allocations
/// from the thread cache. On the protocol benchmark that measured about +2%
/// HTTPS/1.1 throughput at 10 KiB payloads (inside the benchmark's ±3%
/// resolution) and was neutral at larger sizes. The cache holds only size
/// classes a thread actually uses and is trimmed by jemalloc's incremental
/// thread-cache GC. `_RJEM_MALLOC_CONF` still overrides any option at runtime.
#[cfg(not(windows))]
#[repr(transparent)]
pub struct JemallocConf(*const std::ffi::c_char);

// SAFETY: the pointer refers to a `'static` NUL-terminated literal that is
// never written; jemalloc reads it once during its own initialization.
#[cfg(not(windows))]
unsafe impl Sync for JemallocConf {}

/// Read by jemalloc as `const char *malloc_conf` (prefixed `_rjem_`).
#[cfg(not(windows))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static malloc_conf: JemallocConf = JemallocConf(c"tcache_max:131072".as_ptr());

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
