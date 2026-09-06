// Use jemalloc as the global allocator on non-Windows platforms.
// jemalloc significantly reduces memory fragmentation under high-concurrency
// workloads compared to the system allocator, which matters for a proxy that
// creates/destroys many small allocations (headers, buffers) per request.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    ferrum_edge::run_gateway_cli();
}
