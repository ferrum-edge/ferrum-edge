"""Hosted-only, branch-only source experiment for #6022; never imported by Edge."""
import os
from pathlib import Path
import re

variant = os.environ['STACK_VARIANT']
assert variant in {'control', 'frontend', 'routing-dispatch', 'direct-h1', 'direct-h2', 'h3-exchange'}
proxy = Path('src/proxy/mod.rs')
client = Path('src/http3/client.rs')
source = proxy.read_text()
if variant == 'frontend':
    start = source.index('fn boxed_handle_proxy_request_on_frontend_port(')
    end = source.index('\n/// Compiled coroutine sizes', start)
    block = source[start:end]
    old = 'Box::pin(handle_proxy_request_on_frontend_port('
    assert block.count(old) == 1 and block.count('    ))\n}') == 1
    block = block.replace(old, 'handle_proxy_request_on_frontend_port(').replace('    ))\n}', '    )\n}')
    source = source[:start] + block + source[end:]
elif variant in {'routing-dispatch', 'direct-h1', 'direct-h2'}:
    target = {'routing-dispatch': 'proxy_to_backend', 'direct-h1': 'proxy_to_backend_direct_h1', 'direct-h2': 'proxy_to_backend_http2'}[variant]
    pattern = r'boxed_proxy_future(?=\(\|\| \{\s*' + target + r'\()'
    source, count = re.subn(pattern, 'unboxed_stack_probe_future', source)
    expected = {'routing-dispatch': 2, 'direct-h1': 1, 'direct-h2': 1}[variant]
    assert count == expected, (variant, count, expected)
    marker = '/// Construct and box a concrete child future in a separate synchronous frame.'
    factory = '#[inline(never)]\nfn unboxed_stack_probe_future<F: std::future::Future>(construct: impl FnOnce() -> F) -> F {\n    construct()\n}\n\n'
    assert source.count(marker) == 1
    source = source.replace(marker, factory + marker)
elif variant == 'h3-exchange':
    h3 = client.read_text()
    h3, count = re.subn(r'boxed_h3_future(?=\(\|\| \{\s*Self::do_request(?:_streaming)?\()', 'unboxed_stack_probe_future', h3)
    assert count == 2, count
    marker = 'fn boxed_h3_future<F>'
    pos = h3.index('#[inline(never)]\n' + marker)
    factory = '#[inline(never)]\nfn unboxed_stack_probe_future<F: std::future::Future>(construct: impl FnOnce() -> F) -> F {\n    construct()\n}\n\n'
    client.write_text(h3[:pos] + factory + h3[pos:])
proxy.write_text(source)

# Print every independent state size even if a later ceiling fails. The
# frontend probe removes the pointer by design; test the existing frontend
# state ceiling for its outer boundary instead of asserting pointer identity.
path = Path('tests/unit/gateway_core/frontend_affinity_tests.rs')
text = path.read_text()
anchor = '    assert_eq!(boxed_frontend, std::mem::size_of::<usize>());'
assert text.count(anchor) == 1
report = '    eprintln!("STACK_PROBE frontend_boundary={boxed_frontend} frontend={frontend} handler={handler} backend={backend}");\n'
replacement = report + ('    assert!(boxed_frontend <= 8 * 1024);' if variant == 'frontend' else anchor)
path.write_text(text.replace(anchor, replacement))
path = Path('tests/integration/http3_integration_tests.rs')
text = path.read_text()
anchor = '    let sizes = Http3ConnectionPool::buffered_dispatch_future_sizes_for_test();'
assert text.count(anchor) == 1
path.write_text(text.replace(anchor, anchor + '\n    eprintln!("STACK_PROBE h3_sizes={sizes:?}");'))
print('Applied isolated stack-box variant:', variant)
