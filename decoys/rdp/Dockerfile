# syntax=docker/dockerfile:1
#
# RDP decoy backed by OpenCanary's rdp module.
#
# The module mimics an NLA-enabled RDP server and always answers with a login
# failure. It parses the X.224 connection request cookie, so when a client sends
# "Cookie: mstshash=<user>" (which mstsc.exe and xfreerdp do), the attempted
# username is extracted and logged.
#
# Note this is a protocol responder, not a full RDP stack: it will not paint a
# desktop. It exists to look real to scanners and to capture usernames.

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

FROM python:3.12-slim
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN mkdir -p /etc/opencanaryd
COPY opencanary.conf /etc/opencanaryd/opencanary.conf

EXPOSE 3389

ENTRYPOINT ["opencanaryd", "--dev"]
