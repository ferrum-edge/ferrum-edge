# Payload Size Performance Tests

Measures gateway throughput and latency across different **content types** and **payload sizes** (10KB → 9MB). Each test sends realistic, structurally valid payloads through the gateway and compares against a direct-to-backend baseline.

## Quick Start

```bash
# Build everything and run all tier 1 tests (includes TCP, UDP)
bash run_payload_test.sh tier1

# Run a specific content type
bash run_payload_test.sh json --duration 30 --concurrency 200

# Run all tiers
bash run_payload_test.sh all

# Run all HTTP content types over HTTP/2
bash run_payload_test.sh http2 --duration 20

# Run HTTP content types over HTTP/3 (QUIC)
bash run_payload_test.sh http3

# Run ALL protocols (HTTP/1.1 + HTTP/2 + HTTP/3 + gRPC + WS + TCP + UDP)
bash run_payload_test.sh all-protocols --duration 10

# Skip rebuild for iteration
bash run_payload_test.sh grpc --skip-build --duration 15
```

## Content Type Tiers

### Tier 1 — Must Be Perfect
| Content Type | Protocol | Description |
|---|---|---|
| `json` | HTTP/1.1 | `application/json` — most common API format |
| `octet-stream` | HTTP/1.1 | `application/octet-stream` — binary blobs, file downloads |
| `ndjson` | HTTP/1.1 | `application/x-ndjson` — newline-delimited JSON streaming |
| `grpc` | gRPC (h2c) | `application/grpc` — protobuf over HTTP/2 |
| `ws-binary` | WebSocket | Binary WebSocket frames |
| `tcp` | TCP | Raw TCP stream echo |
| `udp` | UDP | Raw UDP datagram echo (max 64KB per datagram) |

### Tier 2 — Important
| Content Type | Protocol | Description |
|---|---|---|
| `multipart` | HTTP/1.1 | `multipart/form-data` — file uploads |
| `form-urlencoded` | HTTP/1.1 | `application/x-www-form-urlencoded` — HTML forms |

### Tier 3 — Enterprise Differentiator
| Content Type | Protocol | Description |
|---|---|---|
| `xml` | HTTP/1.1 | `application/xml` — legacy APIs |
| `soap-xml` | HTTP/1.1 | `application/soap+xml` — SOAP web services |
| `graphql` | HTTP/1.1 | `application/graphql` — GraphQL mutations with large variables |

## Payload Sizes

| Label | Bytes | Use Case |
|---|---|---|
| 10KB | 10,240 | Typical JSON API response |
| 50KB | 51,200 | Medium API payload, small file |
| 100KB | 102,400 | Large API response, image metadata |
| 1MB | 1,048,576 | Document upload, large JSON batch |
| 5MB | 5,242,880 | Image upload, data export |
| 9MB | 9,437,184 | Large file upload, video thumbnail |

## Options

| Flag | Default | Description |
|---|---|---|
| `--duration <SECS>` | 15 | Test duration per size point |
| `--concurrency <N>` | 100 | Concurrent connections |
| `--sizes <S1,S2,...>` | 10kb,50kb,100kb,1mb,5mb,9mb | Comma-separated size list |
| `--skip-build` | false | Skip cargo build step |
| `--skip-direct` | false | Skip direct-to-backend baseline |
| `--json` | false | Machine-readable JSON output |
| `--results-dir <DIR>` | ./results | Where to write JSON results |

## Architecture

```
Client (payload_bench) → Gateway (ferrum-edge) → Backend (payload_backend)
                       ↕                        ↕
                   Port 8000  (HTTP)         Port 4001 (HTTP/1.1)
                   Port 8443  (HTTPS/H2/H3)  Port 4443 (HTTPS/H2)
                   Port 5010  (TCP proxy)    Port 4445 (HTTP/3 QUIC)
                   Port 5003  (UDP proxy)    Port 50053 (gRPC)
                                             Port 4003 (WebSocket)
                                             Port 4004 (TCP echo)
                                             Port 4005 (UDP echo)
                                             Port 4010 (Health)
```

### Protocol Groups

| Group | Command | Protocols Tested |
|---|---|---|
| `tier1` | `bash run_payload_test.sh tier1` | HTTP/1.1, gRPC, WebSocket, TCP, UDP |
| `http2` | `bash run_payload_test.sh http2` | HTTP/2 for all HTTP content types |
| `http3` | `bash run_payload_test.sh http3` | HTTP/3 (QUIC) for json, octet-stream, ndjson, xml |
| `all-protocols` | `bash run_payload_test.sh all-protocols` | HTTP/1.1 + HTTP/2 + HTTP/3 + gRPC + WS + TCP + UDP |

### Payload Generation

Each content type generates structurally valid data:

- **JSON**: Nested objects with `records` array, realistic field names
- **XML**: Well-formed XML with `<?xml?>` header, nested `<record>` elements
- **Form-urlencoded**: `key=value&data=<padding>` with URL-safe characters
- **Multipart**: Standard multipart boundary with metadata JSON part + binary file part
- **Octet-stream**: Random binary data
- **gRPC**: Protobuf `EchoRequest` with `bytes payload` field
- **SSE**: `id: N\nevent: message\ndata: {...}\n\n` formatted events
- **NDJSON**: One JSON object per line with `\n` separators
- **SOAP+XML**: Full SOAP envelope with header/body and `<DataItem>` elements
- **GraphQL**: JSON-encoded `{"query":"...","variables":{"input":{"items":[...]}}}` mutation

### Backend Behavior

The backend echoes each request body back with the same `Content-Type` header and approximately the same payload size. For gRPC, it echoes the protobuf `payload` bytes field. For WebSocket, it echoes binary frames. TCP uses `io::copy` for bidirectional echo. UDP echoes each datagram back to the sender.

## Output

Results are printed as formatted tables per content type:

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║  Tier 1: application/json (http1)                                                                      ║
╠══════════╦════════════╦══════════════╦══════════╦══════════╦══════════╦═══════════════╦═════════════════╣
║ Size     ║ RPS (gw)   ║ RPS (direct) ║ Overhead ║ P50      ║ P99      ║ Throughput    ║ Errors          ║
╠══════════╬════════════╬══════════════╬══════════╬══════════╬══════════╬═══════════════╬═════════════════╣
║ 10KB     ║     45,000 ║       52,000 ║    13.5% ║   1.20ms ║   5.80ms ║    430.0 Mbps ║               0 ║
║ 50KB     ║     38,000 ║       44,000 ║    13.6% ║   1.50ms ║   7.20ms ║  1,520.0 Mbps ║               0 ║
║ ...      ║        ... ║          ... ║      ... ║      ... ║      ... ║           ... ║             ... ║
╚══════════╩════════════╩══════════════╩══════════╩══════════╩══════════╩═══════════════╩═════════════════╝
```

JSON results are also saved to `./results/` for programmatic analysis.
