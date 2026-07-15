# syntax=docker/dockerfile:1
#
# SMB decoy: real Samba + OpenCanary's smb module.
#
# IMPORTANT: OpenCanary's smb module is a log watcher, not an SMB
# implementation. See opencanary/modules/samba.py: it tails an audit file and
# parses "smbd_audit" lines produced by Samba's full_audit VFS module. So this
# image runs three processes under supervisord (rsyslogd, smbd, opencanaryd).
# This is the only one of the three decoys that cannot be a single process.

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

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba \
        samba-common-bin \
        samba-vfs-modules \
        rsyslog \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf
COPY rsyslog-samba.conf /etc/rsyslog.conf
COPY opencanary.conf /etc/opencanaryd/opencanary.conf
# Replace the main config rather than dropping into conf.d: the [supervisord]
# section (nodaemon=true) is only honoured in the primary config file.
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Pre-create the audit file so OpenCanary's FileSystemWatcher has something to
# attach to at startup, before smbd has emitted anything.
RUN mkdir -p /var/log/samba /var/run/samba /var/spool/rsyslog \
        /srv/share/hr /srv/share/backups \
    && touch /var/log/samba-audit.log

# Bait content. Filenames are the lure; opening any of these is audited and
# surfaces as an OpenCanary event with USER, SHARENAME, and FILENAME.
RUN printf 'employee,salary,ssn\n' > /srv/share/hr/payroll_2026_Q1.csv \
    && printf 'placeholder\n' > /srv/share/hr/salary_review_confidential.xlsx \
    && printf 'placeholder\n' > /srv/share/backups/domain_controller_backup.bak \
    && chmod -R a+r /srv/share

# Fail the build rather than ship a broken smb.conf.
RUN testparm -s /etc/samba/smb.conf > /dev/null

EXPOSE 445

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
