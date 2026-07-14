.PHONY: help build up down logs ps bpf broker-fmt clean

help:
	@echo "Targets:"
	@echo "  build      Build all container images"
	@echo "  up         Start the decoy stack in the background"
	@echo "  down       Stop and remove the stack"
	@echo "  logs       Follow broker logs"
	@echo "  ps         Show stack status"
	@echo "  bpf        Compile the eBPF object locally (needs clang + libbpf-dev)"
	@echo "  broker-fmt Format the Go broker sources"
	@echo "  clean      Remove local build artifacts"

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f broker

ps:
	docker compose ps

bpf:
	@ARCH="$$(uname -m)"; \
	case "$$ARCH" in \
		x86_64)  TARGET_ARCH=x86 ;; \
		aarch64) TARGET_ARCH=arm64 ;; \
		*) echo "unsupported architecture: $$ARCH" >&2; exit 1 ;; \
	esac; \
	echo "building eBPF for $$ARCH (__TARGET_ARCH_$$TARGET_ARCH)"; \
	clang -O2 -g -target bpf \
		-D__TARGET_ARCH_$$TARGET_ARCH \
		-I/usr/include/$$ARCH-linux-gnu \
		-c broker/bpf/decoy.bpf.c -o broker/bpf/decoy.bpf.o

broker-fmt:
	cd broker && gofmt -w .

clean:
	rm -f broker/bpf/decoy.bpf.o
