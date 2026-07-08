GO ?= go
BPFTOOL ?= bpftool

.PHONY: all build generate vmlinux deps test clean run

all: build

# Regenerate vmlinux.h from the running kernel's BTF.
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Compile the eBPF C to a CO-RE object and (re)generate Go bindings.
generate:
	$(GO) generate ./...

build: generate
	$(GO) build -o tlstat .

test:
	$(GO) test ./internal/...

# Install the build toolchain (Debian/Ubuntu).
deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libelf-dev libbpf-dev linux-tools-common

run: build
	sudo ./tlstat

clean:
	rm -f tlstat internal/loader/tlstat_*.o
