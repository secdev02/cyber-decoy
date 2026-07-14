# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY common/responder.py /app/responder.py
# SMB negotiation is binary, so the placeholder just logs and drains bytes.
ENV DECOY_NAME=smb \
    DECOY_PORT=445 \
    DECOY_BANNER=""
EXPOSE 445
ENTRYPOINT ["python3", "/app/responder.py"]
