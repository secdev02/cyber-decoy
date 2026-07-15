# syntax=docker/dockerfile:1
#
# SMB decoy: a single Python process running Impacket's SimpleSMBServer.
# This replaces the previous Samba + rsyslog + supervisord + OpenCanary stack.
FROM python:3.12-slim

# Impacket has no compiled extensions of its own, but a couple of its
# dependencies (pycryptodomex) ship wheels, so no build toolchain is needed.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Non-root user. The decoy binds 445, a privileged port, so the container is
# granted NET_BIND_SERVICE in docker-compose.yml rather than running as root.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin decoy

# Decoy share tree. Read-only bait content. Keep it small and boring.
RUN mkdir -p /srv/share/hr /srv/share/backups /srv/share/it \
    && printf 'employee,salary,ssn\n' > /srv/share/hr/payroll_2026_Q1.csv \
    && printf 'see IT before restoring\n' > /srv/share/backups/README.txt \
    && printf 'domain admin creds rotation schedule\n' > /srv/share/it/notes.txt \
    && chown -R decoy:decoy /srv/share

COPY smb_decoy.py /app/smb_decoy.py

USER decoy
EXPOSE 445
ENTRYPOINT ["python3", "/app/smb_decoy.py"]
