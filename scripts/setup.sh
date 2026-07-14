#!/usr/bin/env bash
#
# Preflight checks for the cyber-decoy host. Verifies kernel version, BPF
# filesystem, Docker, and warns about ports already in use.
set -euo pipefail

ok()   { printf '  [ok]  %s\n' "$1"; }
warn() { printf '  [!!]  %s\n' "$1"; }

echo "cyber-decoy preflight"
echo

# Kernel version. TCX attach needs 6.6 or newer.
kernel="$(uname -r)"
major="$(echo "$kernel" | cut -d. -f1)"
minor="$(echo "$kernel" | cut -d. -f2)"
if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 6 ]; }; then
    ok "kernel $kernel supports TCX eBPF attach"
else
    warn "kernel $kernel is older than 6.6; eBPF observation will be skipped, proxy still works"
fi

# BPF filesystem.
if mount | grep -q 'type bpf'; then
    ok "bpf filesystem mounted"
else
    warn "bpf filesystem not mounted; run: sudo mount -t bpf bpf /sys/fs/bpf"
fi

# Docker and compose.
if command -v docker >/dev/null 2>&1; then
    ok "docker present"
else
    warn "docker not found"
fi
if docker compose version >/dev/null 2>&1; then
    ok "docker compose present"
else
    warn "docker compose plugin not found"
fi

# Port availability.
for port in 22 3389 445; do
    if ss -ltn 2>/dev/null | grep -q ":$port "; then
        warn "port $port already in use on host (SSH on 22 is common; remap in docker-compose.yml)"
    else
        ok "port $port free"
    fi
done

echo
echo "done"
