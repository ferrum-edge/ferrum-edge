#!/usr/bin/env python3
"""Minimal HTTP/1 echo backend for launch-readiness probes. Not an exploit."""

import json
import socket
import sys
import threading


def handle(conn: socket.socket, marker: str) -> None:
    try:
        conn.settimeout(2.0)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        text = data.decode("latin1", errors="replace")
        first = text.split("\r\n", 1)[0]
        headers = {}
        for line in text.split("\r\n")[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body_obj = {
            "marker": marker,
            "request_line": first,
            "host": headers.get("host"),
            "header_names": sorted(headers.keys()),
        }
        body = json.dumps(body_obj)
        resp = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: application/json\r\n"
            f"X-Backend-Marker: {marker}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        conn.sendall(resp.encode("utf-8"))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port: int, marker: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn, marker), daemon=True).start()


def main() -> None:
    port = int(sys.argv[1])
    marker = sys.argv[2] if len(sys.argv) > 2 else "echo"
    serve(port, marker)


if __name__ == "__main__":
    main()
