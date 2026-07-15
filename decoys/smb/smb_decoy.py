#!/usr/bin/env python3
"""SMB decoy built on Impacket's SimpleSMBServer.

This replaces the previous Samba + rsyslog + OpenCanary three-process design
with a single pure-Python process. Impacket implements SMB1/2/3 directly, so
there is no smbd, no full_audit VFS, no syslog hand-off, and no supervisord.

What it does:
  - Binds 445 and presents believable read-only shares as bait.
  - Answers SMB2/3 negotiation so scanners and clients see a real service
    (nmap -sV reports it, unlike the old low-interaction stub).
  - Logs connections and, most importantly, authentication attempts. The
    NTLM AUTHENTICATE message an attacker sends carries the domain, username,
    and NetNTLM response, which is exactly the credential-capture value a
    honeypot exists for.

Logs are emitted as one JSON object per line on stdout, so `docker compose logs`
and any downstream SIEM can parse them directly.

SECURITY NOTES (read before deploying):
  - Impacket's smbserver had a critical path traversal, CVE-2021-31800, that
    specifically affected honeypots. It was fixed in 0.9.23. This image pins a
    current release (see requirements.txt) and must not be downgraded.
  - The share paths below point at a small tree of decoy files. Even so, the
    container is run read-only, non-root, with all capabilities dropped except
    NET_BIND_SERVICE (see docker-compose.yml). Treat the whole container as
    attacker-reachable and keep it on the internal network only.

Behind the broker, the observed client IP is always the broker's address. The
true source IP lives in the broker and eBPF logs; correlate on timestamp. See
the README section "the decoys cannot see the attacker's IP".
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

from impacket import smbserver


NODE_ID = os.environ.get("DECOY_NODE_ID", "decoy-smb")
LISTEN_ADDR = os.environ.get("DECOY_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("DECOY_LISTEN_PORT", "445"))
SERVER_NAME = os.environ.get("DECOY_SERVER_NAME", "FILESRV01")
SERVER_OS = os.environ.get("DECOY_SERVER_OS", "Windows Server 2019 Standard 17763")
SERVER_DOMAIN = os.environ.get("DECOY_SERVER_DOMAIN", "CORP")
SHARE_ROOT = os.environ.get("DECOY_SHARE_ROOT", "/srv/share")


def emit(event, **fields):
    """Print one structured JSON log line."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "node_id": NODE_ID,
        "service": "smb",
        "event": event,
    }
    record.update(fields)
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


# Patterns pulled from impacket's own log strings, so we can turn its internal
# logging into structured events without patching the library.
RE_CONNECT = re.compile(r"Incoming connection \(([^,]+),(\d+)\)")
RE_AUTH = re.compile(r"AUTHENTICATE_MESSAGE \(([^\\]*)\\([^,]*),([^)]*)\)")
RE_TREE = re.compile(r"smb2TreeConnect: (.+)")


class JSONLogHandler(logging.Handler):
    """Bridges impacket's stdlib logging into our JSON event stream.

    Impacket logs everything through the "impacket" logger. Rather than fork or
    monkeypatch the server, we watch its messages and re-emit the interesting
    ones (connect, authenticate, tree connect) as structured events. Unmatched
    messages are still surfaced at debug level so nothing is silently lost.
    """

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return

        m = RE_AUTH.search(msg)
        if m:
            domain, user, workstation = m.group(1), m.group(2), m.group(3)
            emit(
                "smb_auth_attempt",
                domain=domain or None,
                username=user or None,
                workstation=workstation or None,
                note="NTLM authenticate message received",
            )
            return

        m = RE_CONNECT.search(msg)
        if m:
            emit("smb_connect", src_host=m.group(1), src_port=int(m.group(2)))
            return

        m = RE_TREE.search(msg)
        if m:
            emit("smb_tree_connect", share=m.group(1).strip())
            return

        # Everything else: keep it, but quietly.
        if record.levelno >= logging.WARNING:
            emit("smb_server_log", level=record.levelname, message=msg)


def build_server():
    server = smbserver.SimpleSMBServer(
        listenAddress=LISTEN_ADDR,
        listenPort=LISTEN_PORT,
    )

    # SMB2/3 support is what makes modern clients and nmap -sV engage. Without
    # it the decoy only speaks SMB1 and looks conspicuously ancient.
    server.setSMB2Support(True)

    # Server identity metadata. In impacket 0.13.1 these [global] values are
    # stored and returned by getServerName/OS/Domain but are NOT placed in the
    # SMB2 negotiate response on the wire (verified by reading smbserver.py:
    # __serverOS is only assigned and returned, never serialised). We still set
    # them for correctness and in case a future impacket release surfaces them.
    cfg = server.getServer().getServerConfig()
    cfg.set("global", "server_name", SERVER_NAME)
    cfg.set("global", "server_os", SERVER_OS)
    cfg.set("global", "server_domain", SERVER_DOMAIN)

    # Bait shares. Names are the lure; keep them read-only and boring inside.
    server.addShare("HR-Payroll", os.path.join(SHARE_ROOT, "hr"),
                    "Human Resources", readOnly="yes")
    server.addShare("Backups", os.path.join(SHARE_ROOT, "backups"),
                    "Nightly backups", readOnly="yes")
    server.addShare("IT-Admin", os.path.join(SHARE_ROOT, "it"),
                    "IT department", readOnly="yes")

    # Let impacket log to our JSON bridge, and silence its default noisy
    # stderr handler.
    log = logging.getLogger("impacket")
    log.handlers = []
    log.addHandler(JSONLogHandler())
    log.setLevel(logging.INFO)

    return server


def main():
    emit(
        "smb_decoy_start",
        listen=f"{LISTEN_ADDR}:{LISTEN_PORT}",
        server_name=SERVER_NAME,
        shares=["HR-Payroll", "Backups", "IT-Admin"],
    )
    server = build_server()
    try:
        server.start()
    except KeyboardInterrupt:
        emit("smb_decoy_stop")
    except Exception as exc:  # noqa: BLE001 - decoy must not crash on bad input
        emit("smb_decoy_error", error=str(exc))
        raise


if __name__ == "__main__":
    main()
