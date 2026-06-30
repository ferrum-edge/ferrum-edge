# Summary

- add `RequestStream::peek_recv_trailers()` to expose already-buffered trailer HEADERS without consuming them
- expose the method through both `client::RequestStream` and `server::RequestStream`
- preserve normal `poll_recv_trailers` behavior for callers that continue waiting for FIN

Fixes #NNN.

# Motivation

`poll_recv_trailers` intentionally waits for terminal FIN after receiving trailer
HEADERS so it can reject known frames that appear after trailers. Applications
with their own trailer wait timeout still need a way to preserve trailers that
were already received before that timeout fired.

The new API decodes a clone of the buffered trailer block and leaves stream
state untouched.

# Testing

- `cargo test -p h3`
