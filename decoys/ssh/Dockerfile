# syntax=docker/dockerfile:1
#
# SSH decoy backed by OpenCanary's ssh module (twisted.conch).
#
# Unlike a banner-only stub, this completes a real SSH key exchange, so
# "nmap -sV" reports a genuine OpenSSH service and real clients get far enough
# to submit credentials, which are logged as JSON (logtype 4002).

# Stage 1: build the virtualenv. python:3.12-slim has no compiler, and a few of
# OpenCanary's dependencies (simplejson, ntlmlib, fpdf) build from source, so the
# toolchain is needed here and discarded afterwards.
FROM python:3.12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip wheel \
    && pip install --no-cache-dir opencanary

# Stage 2: runtime, no compiler.
FROM python:3.12-slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# OpenCanary searches /etc/opencanaryd/opencanary.conf first. Using it avoids
# the "config file in the immediate directory is not recommended" warning.
# /var/lib/opencanary/ssh_keys must exist before startup: getRSAKeys() in
# opencanary/modules/ssh.py opens the key files directly and does not create
# intermediate directories.
RUN mkdir -p /etc/opencanaryd /var/lib/opencanary/ssh_keys
COPY opencanary.conf /etc/opencanaryd/opencanary.conf

# ssh.key_path lives here. Mount a volume on /var/lib/opencanary to keep a
# stable host key fingerprint across restarts; a fingerprint that changes on
# every restart is a tell that the service is fake.
VOLUME ["/var/lib/opencanary"]

EXPOSE 2222

# --dev runs in the foreground and logs to stdout, which is what Docker wants.
# (opencanaryd --start daemonizes via twistd and the container would exit.)
ENTRYPOINT ["opencanaryd", "--dev"]
