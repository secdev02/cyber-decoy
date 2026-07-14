# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY common/responder.py /app/responder.py
ENV DECOY_NAME=ssh \
    DECOY_PORT=2222 \
    DECOY_BANNER="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
EXPOSE 2222
ENTRYPOINT ["python3", "/app/responder.py"]
