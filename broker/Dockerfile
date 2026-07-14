# syntax=docker/dockerfile:1

# Stage 1: compile the eBPF object with clang.
# Only clang and libbpf-dev are required. Notably NOT gcc-multilib, which is an
# x86-only package (it provides i386 support) and has no arm64 candidate, so
# installing it breaks the build on Apple Silicon and other arm64 hosts.
FROM ubuntu:24.04 AS bpf-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libbpf-dev \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY bpf/decoy.bpf.c ./bpf/decoy.bpf.c
# Detect the build architecture and pass the matching __TARGET_ARCH_* macro and
# include path. The "-target bpf" output itself is architecture neutral.
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
        x86_64)  TARGET_ARCH=x86   ;; \
        aarch64) TARGET_ARCH=arm64 ;; \
        *) echo "unsupported architecture: $ARCH" >&2 && exit 1 ;; \
    esac && \
    echo "building eBPF for $ARCH (__TARGET_ARCH_$TARGET_ARCH)" && \
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_$TARGET_ARCH \
        -I/usr/include/$ARCH-linux-gnu \
        -c bpf/decoy.bpf.c -o decoy.bpf.o

# Stage 2: build the Go broker.
# go.sum is resolved here rather than being required up front, so a fresh clone
# builds without a local Go toolchain. This trades dependency layer caching for
# robustness; if you commit a go.sum and want caching back, restore the usual
# "COPY go.mod go.sum ./ && go mod download" split before copying sources.
FROM golang:1.22-bookworm AS go-builder
WORKDIR /src
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /out/broker ./

# Stage 3: minimal runtime.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/decoy
COPY --from=go-builder /out/broker /usr/local/bin/broker
COPY --from=bpf-builder /src/decoy.bpf.o /opt/decoy/decoy.bpf.o
COPY config.yaml /opt/decoy/config.yaml
ENTRYPOINT ["/usr/local/bin/broker", "-config", "/opt/decoy/config.yaml"]
