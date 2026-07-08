// Package loader compiles and loads the tlstat eBPF programs.
package loader

// Generate Go bindings and the compiled CO-RE object from the eBPF C source.
// The -type flags emit Go structs that mirror the __packed C structs exactly.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type flow -type ssl_stat -type wire_event -type data_event tlstat ../../bpf/tlstat.bpf.c -- -I../../bpf -O2 -g -Wall -Wno-unused-function -Wno-address-of-packed-member
