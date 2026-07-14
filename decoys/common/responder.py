#!/usr/bin/env python3
"""Minimal placeholder decoy.

Listens on a TCP port, logs every connection and the first bytes received, and
optionally replies with a service banner. This is intentionally low-interaction.
Swap it for a real emulator in production (see the README for suggestions such
as Cowrie for SSH, RDPy for RDP, and Dionaea or Heralding for SMB).

Configured entirely through environment variables so one image serves all three
roles:

    DECOY_NAME    label used in logs (default "decoy")
    DECOY_PORT    TCP port to bind (default 9000)
    DECOY_BANNER  optional bytes to send on connect (supports \\r\\n escapes)
    DECOY_READ    max bytes to read and log per connection (default 4096)
"""

import os
import socket
import sys
import threading
from datetime import datetime, timezone


def log(name, message):
    stamp = datetime.now(timezone.utc).isoformat()
    print("[{0}] {1} {2}".format(stamp, name, message), flush=True)


def handle(conn, addr, name, banner, read_limit):
    peer = "{0}:{1}".format(addr[0], addr[1])
    log(name, "connect from " + peer)
    try:
        if banner:
            conn.sendall(banner)
        conn.settimeout(10)
        data = conn.recv(read_limit)
        if data:
            preview = data[:200].hex()
            log(name, "recv {0} bytes from {1} hex={2}".format(len(data), peer, preview))
    except (socket.timeout, ConnectionError) as exc:
        log(name, "session error from {0}: {1}".format(peer, exc))
    finally:
        conn.close()
        log(name, "close " + peer)


def parse_banner(raw):
    if not raw:
        return b""
    return raw.encode("utf-8").decode("unicode_escape").encode("latin-1")


def main():
    name = os.environ.get("DECOY_NAME", "decoy")
    port = int(os.environ.get("DECOY_PORT", "9000"))
    banner = parse_banner(os.environ.get("DECOY_BANNER", ""))
    read_limit = int(os.environ.get("DECOY_READ", "4096"))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    log(name, "listening on 0.0.0.0:{0}".format(port))

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle,
                args=(conn, addr, name, banner, read_limit),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        log(name, "shutting down")
        srv.close()
        sys.exit(0)


if __name__ == "__main__":
    main()
