# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY common/responder.py /app/responder.py
# RDP has no plaintext banner, so the placeholder just logs and drains bytes.
ENV DECOY_NAME=rdp \
    DECOY_PORT=3389 \
    DECOY_BANNER=""
EXPOSE 3389
ENTRYPOINT ["python3", "/app/responder.py"]
