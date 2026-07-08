# tlstat — Design & Specification

Reference for extending tlstat. Read this before adding features so you don't
re-introduce the subtle bugs that took real effort to find (see **Gotchas**).

## 1. Purpose

A `sudo`-run, `htop`-style TUI that monitors TLS handshakes and connections on a
Linux host in real time. For each connection it shows endpoints, server
identity, negotiated crypto, live byte counts, and — for OpenSSL apps — the
**cleartext before encryption**. Handles both connections opened while running
(full handshake parse) and pre-existing ones (best-effort, fields unknown).

## 2. Core idea: two eBPF vantage points, one table

TLS requirements split across two attachment strategies that answer different
questions. This split is the central design fact.

| Need | Mechanism | Where |
|------|-----------|-------|
| bytes in/out, connection discovery | kprobe `tcp_sendmsg`/`tcp_recvmsg`, tracepoint `inet_sock_set_state` | wire |
| handshake crypto (SNI, versions, ciphers, groups, sig algs, TLS 1.2 cert) | capture early wire bytes → parse in userspace | wire |
| **cleartext application data** | uprobe `SSL_write`/`SSL_read` in `libssl.so` | library |

Nothing at the kernel/wire layer can ever yield plaintext — that is the whole
point of TLS. Plaintext *only* comes from the library uprobe. Conversely, the
uprobe sees app data but not handshake messages, so handshake crypto *only*
comes from wire parsing. You need both.

Everything is keyed on the kernel `struct sock *` pointer, which is stable for a
connection's lifetime and identical across all three kernel programs. Plaintext
(which only knows `SSL*`/pid/fd) is correlated back to a `sock` separately — see
§6.

## 3. Data flow

```
          kernel (eBPF, CO-RE)                        userspace (Go)
  ┌─────────────────────────────────┐        ┌──────────────────────────────┐
  │ kprobe tcp_sendmsg/recvmsg       │──bytes→│ flows map  ─poll→ Store       │
  │   → flows map (per-sock counters)│        │            .UpdateFlows()     │
  │   → wire_event (first chunks)    │──ring─→│ Store.ApplyWire() → tlsparse  │
  │ tracepoint inet_sock_set_state   │        │                               │
  │   → flows (direction, closed)    │        │                               │
  │ uprobe SSL_set_fd → ssl_fds      │        │                               │
  │ uprobe SSL_write/SSL_read        │──ring─→│ Store.ApplyData() (by SSL*)   │
  │   → data_event + ssl_stats map   │──poll─→│ Store.UpdateSSLStats() (join) │
  └─────────────────────────────────┘        │                               │
                                              │ Store.Snapshot() → bubbletea  │
                                              └──────────────────────────────┘
```

- **Ring buffer** (`events`, 16 MiB) carries low-volume, payload-bearing events:
  `wire_event` (handshake bytes) and `data_event` (plaintext samples).
- **Maps polled each tick** (`flows`, `ssl_stats`) carry high-frequency counters
  — polling avoids an event per packet.

## 4. Repository layout

```
bpf/tlstat.bpf.c      all eBPF programs (kprobes, tracepoint, uprobes) + maps
bpf/tlstat.h          C structs shared with Go; MUST stay __packed
bpf/vmlinux.h         generated: bpftool btf dump ... (regen via `make vmlinux`)
internal/loader/
  gen.go              //go:generate bpf2go directive (-target amd64, -type ...)
  tlstat_x86_bpfel.go GENERATED — do not edit; rerun `go generate`
  loader.go           load/attach, ring reader, map snapshots; EXPORTED types
internal/tlsparse/    TLS record/handshake parser + IANA name tables (pure, tested)
internal/model/
  model.go            Store: connection table, event merge, plaintext join
  proc.go             /proc-based (pid,fd)→remote-endpoint resolution
internal/ui/          bubbletea Model/View: table + detail pane + peek
main.go               root check, wiring, goroutines, TUI + headless --dump
```

### Package boundaries
- `loader` exposes **exported** plain structs (`Flow`, `SSLStat`, `WireEvent`,
  `DataEvent`) and converts from the unexported bpf2go types. Other packages
  never touch generated types.
- `tlsparse` is pure and unit-tested (`parse_test.go`, `server_test.go`); no
  eBPF or OS deps. Easiest place to work.
- `model` depends on `loader` + `tlsparse`. `ui` depends on `model` + `tlsparse`.

## 5. eBPF details (`bpf/tlstat.bpf.c`)

### Maps
- `events` RINGBUF — wire + data events.
- `flows` HASH `sock* → struct flow` — byte counters, tuple, comm, direction,
  `is_tls`, `closed`, per-direction wire-capture counters.
- `ssl_stats` HASH `SSL* → struct ssl_stat` — plaintext byte totals, pid, fd.
- `ssl_fds` HASH `SSL* → fd` — populated by the `SSL_set_fd` uprobe.
- `recv_ctxs`, `ssl_ctxs` HASH `pid_tgid → …` — scratch for entry→return probe
  pairing (recvmsg buffer ptr; SSL_read buffer ptr).

### Programs
- `k_tcp_sendmsg` / `k_tcp_recvmsg` (+ `kr_tcp_recvmsg`): byte counts + wire
  capture. recvmsg data is only valid on return, so the entry probe stashes the
  destination buffer ptr keyed by pid_tgid and the return probe reads it.
- `tp_inet_sock_set_state`: sets `direction` (SYN_SENT→client, SYN_RECV→server)
  and `closed`. Does **not** fill the tuple (see Gotcha G4).
- `u_ssl_set_fd`: builds `ssl_fds`.
- `u_ssl_write` / `u_ssl_read` (+ `ur_ssl_read`): plaintext capture. SSL_read
  data is valid on return, same stash pattern.

### Helpers
- `flow_get(sk)`: get-or-create a flow entry; **backfills pid/comm/tuple when
  pid==0** because it runs in process context (the tracepoint may have created
  the entry empty in softirq).
- `iter_base(iter)`: pulls the user buffer ptr from a `msghdr` iov_iter; handles
  `ITER_UBUF` and `ITER_IOVEC`.
- `capture_wire(...)`: emits wire chunks; first chunk per direction must look
  like a TLS record, continuations captured unconditionally (see G2).
- `looks_like_tls(hdr)`: content-type 20–23, major version 0x03, minor ≤ 0x04.
- `u_ssl_free`: emits `close_event` with final byte totals, deletes
  `ssl_stats`/`ssl_fds` for the SSL session (see G7).

### Bounded copies (verifier)
Every `bpf_probe_read_user` size is clamped then masked:
```c
__u32 cap = n;
if (cap > WIRE_CAP - 1) cap = WIRE_CAP - 1;
cap &= (WIRE_CAP - 1);   // makes the bound provable to the verifier
```
See G1 for why the mask-only or clamp-only variants are wrong/rejected.

## 6. Correlation (the tricky part)

Handshake + bytes are naturally keyed by `sock`. Plaintext is not — the uprobe
only knows `SSL*`, pid, tid, fd. Two-stage join:

1. **Plaintext sample → SSL\***: `data_event` carries `SSL*`. `Store.ApplyData`
   stashes head (first chunk) + rolling tail in `plainBySSL[SSL*]`, keyed by
   `SSL*` (not sock) so samples survive arriving *before* the flow poll
   discovers the connection (G3).
2. **SSL\* → connection**: `ssl_stats` entries carry `SSL*` + pid + fd.
   `Store.UpdateSSLStats` resolves pid/fd → connection via `resolve()`:
   - Fast path: cached `(pid,fd) → sock`.
   - `/proc/<pid>/fd/<fd>` → socket inode → `/proc/net/tcp{,6}` → remote
     endpoint → match `Conn.Remote` (`proc.go`).
   - Fallback: the pid's single TLS connection (ambiguous → skip).
   Then it copies byte totals and joins the stashed plaintext head/tail.
3. **SSL_free finalization**: for fast connections that close between polls, the
   `close_event` carries final totals. `ApplyClose` attributes them immediately
   and evicts `plainBySSL[SSL*]`. See G7.

`resolve()` is also where multi-connection-per-process correctness lives.

## 7. Key data structures

- `bpf/tlstat.h`: `struct flow`, `struct ssl_stat`, `struct wire_event`,
  `struct data_event`, `struct close_event` — all `__attribute__((packed))`.
  Go parses them at fixed offsets (`loader.go` `le16/le32/le64` + the bpf2go
  `-type` structs). **If you change a struct, keep it packed and update both
  sides.**
- `model.Conn`: the merged per-connection view (endpoints, `Info`, byte
  counters, `HeadOut`/`TailOut`/`HeadIn`/`TailIn`, `Preexisting`, `ClosedAt`).
  `wireOut`/`wireIn` are the per-direction reassembly buffers (unexported, freed
  on retirement to history). `plainFinal` prevents the poll from zeroing totals
  already finalized by `ApplyClose`.
- `tlsparse.Info`: accumulates handshake facts across successive wire buffers;
  updated in place, idempotent, safe to call repeatedly on a growing buffer.

## 8. Design decisions

- **Poll counters, ring payloads.** Byte/plaintext totals live in maps polled at
  ~2–3 Hz; handshake captures, plaintext *samples*, and session-close events go
  through the ring buffer.
- **Parse TLS in userspace.** The verifier makes stateful TLS parsing painful;
  eBPF just ships bytes. `tlsparse` is a plain, testable Go package.
- **Reassemble in userspace.** eBPF captures per-syscall chunks; `model` concats
  them per direction (`maxWireBuf` = 16 KB) and re-parses, because TLS records
  split across syscalls arbitrarily.
- **TLS 1.3 version inference.** ServerHello `legacy_version` is 0x0303; the real
  version is in `supported_versions`, which a large post-quantum key_share can
  push past the captured window. If the cipher is a 1.3-only suite we infer 1.3.
- **`sock` pointer as the universal key.** Simple and consistent; the only thing
  it doesn't cover is plaintext, handled by the SSL\* join.
- **Continuous plaintext emission.** `emit_plaintext` emits a `data_event` for
  *every* `SSL_write`/`SSL_read` call (no per-session cap). Userspace keeps a
  **head** (first chunk per direction — the request line / early data) and a
  **rolling tail** (last `--peek-bytes`, default 8 KB) so both ends of the
  exchange are inspectable. Ring traffic scales with SSL call count, not bytes.
- **`SSL_free` close event.** The `u_ssl_free` uprobe emits a `close_event` with
  the session's final plaintext byte totals, then deletes `ssl_stats`/`ssl_fds`.
  This ensures short-lived connections that close between polls still get their
  plaintext attributed. Userspace handles it in `Store.ApplyClose`, which sets
  `plainFinal` to prevent the next poll from zeroing the already-finalized totals.
- **History ring.** Closed connections are retired from the live `conns` map into
  a `history []*Conn` ring (capped at `--history`, default 500, oldest dropped).
  Wire reassembly buffers are freed; plaintext head/tail survive. A `Tab` toggle
  in the TUI cycles Active / Closed / All views. Closed rows show "Ns ago".

## 9. Gotchas (bugs fixed — do not reintroduce)

- **G1 — masking clamp.** `cap & (SIZE-1)` is modulo, not clamp. With
  `SIZE=1024`, a 1024-byte read masks to **0**. Always clamp to `SIZE-1` first,
  *then* mask. Clamp-only (`if (cap>N) cap=N`) without the mask gets rejected by
  the verifier ("R2 min value is negative"). Use both.
- **G2 — TLS record fragmentation.** OpenSSL reads the 5-byte record header and
  the body in separate `recvmsg` calls; the body doesn't start with a record
  header. Gating *every* chunk on `looks_like_tls` drops all bodies. Gate only
  the first chunk per direction; capture continuations unconditionally.
- **G3 — plaintext timing.** `data_event`s can arrive before the flow poll has
  created the connection. Don't resolve at `ApplyData` time; stash by `SSL*` and
  join during the `ssl_stats` poll.
- **G4 — identity backfill.** The `inet_sock_set_state` tracepoint fires in
  softirq (pid 0) and can create the flow entry first. `flow_get` must backfill
  pid/comm/tuple when `pid==0` from the process-context kprobe. (The tracepoint
  cannot `memcpy` from `ctx+offset` — verifier rejects "modified ctx ptr" — which
  is why the tuple is filled by the kprobe, not the tracepoint.)
- **G5 — packed structs.** C structs are `__packed`; Go reads fixed offsets. Any
  field change must update both `tlstat.h` and the Go decode.
- **G6 — bpf2go target.** Use `-target amd64` (defines `__TARGET_ARCH_x86` for
  `PT_REGS`/`BPF_UPROBE`), not `-target bpfel`. Anchor ring event types in BTF
  with the `_unused_*` globals or `-type` can't find them.
- **G7 — SSL_free vs poll race.** `SSL_free` deletes `ssl_stats` before the next
  poll. Without the `close_event`, a fast connection (e.g. curl) closes before
  the poll ever reads its `ssl_stats` entry, so plaintext totals are lost.
  `ApplyClose` finalizes totals from the ring event; `plainFinal` on the conn
  prevents the next poll's zero-and-reaccumulate from wiping them.

## 10. Known limitations (feature backlog)

- **Cleartext is OpenSSL-only.** GnuTLS, NSS, BoringSSL, and Go's in-binary
  `crypto/tls` are not hooked. See §11 for how to add a library.
- **TLS 1.3 server cert is encrypted on the wire** — SNI is the identity; full
  cert only on TLS 1.2.
- **Pre-existing connections**: no handshake crypto (missed it); bytes +
  plaintext (once uprobe attaches) still work.
- **Handshake reassembly** is best-effort from the first ~16 KB/direction.
- **IPv6**: parsed and formatted, but exercise it — most testing was IPv4.
- **Map growth**: `flows` entries are deleted on TCP close; `ssl_stats`/`ssl_fds`
  are cleaned by the `SSL_free` uprobe. History ring is capped at `--history`.
- **ECH** (encrypted ClientHello) would hide SNI.

## 11. How to add features

### A new TLS library (e.g. GnuTLS)
1. In `tlstat.bpf.c` add uprobes for the send/recv functions, e.g.
   `gnutls_record_send(session, buf, size)` and
   `gnutls_record_recv` (data valid on return — use the stash pattern like
   `SSL_read`). Reuse `emit_plaintext`. The `SSL*` key becomes the session ptr.
2. Resolve the fd for correlation: hook whatever sets the transport fd
   (`gnutls_transport_set_int`) into an `ssl_fds`-style map, or fall back to the
   pid path in `resolve()`.
3. In `loader.go` `attachSSL`, add the library path + symbols. Consider a
   `--gnutls` flag and auto-detection in `main.findLibssl`-style helpers.
4. Nothing in `model`/`ui` needs to change — plaintext flows through the same
   `data_event`/`ssl_stats` path.

### A new handshake field (e.g. OCSP stapling, cert chain depth)
- Work entirely in `tlsparse`. Add the field to `Info`, parse it in
  `handleExtension` or `parseCertificate`, add a name table to `names.go` if
  needed, and surface it in `ui.renderDetail`. Add a case to the existing tests.

### A new UI column or detail row
- Table columns: `ui.go` header + `renderRow` + the `w*` width consts.
- Detail pane: `ui.renderDetail` (uses `lab()` helper).
- Headless mirror: `main.runDump`.

### Getting the TLS 1.3 cert (currently encrypted on wire)
- Add an OpenSSL uprobe on the cert-verify callback or read the negotiated cert
  post-handshake (library-specific, struct-offset fragile). Store into
  `Info.Cert*`. This is the main path to closing the 1.3 identity gap.

### Recording/exporting sessions
- `model.Store.Snapshot()` (live) and `Store.SnapshotHistory()` (retired) are
  the clean tap points for a JSON/CSV exporter or a `--json` streaming mode;
  mirror `runDump`.

## 12. Build / test / verify

```sh
make deps      # clang llvm libelf-dev libbpf-dev  (Go installed separately)
make generate  # bpf2go: compile eBPF CO-RE + regenerate Go bindings
make build     # generate + go build -o tlstat
make test      # go test ./internal/...   (tlsparse has real coverage)
sudo ./tlstat  # interactive TUI
```

### Fast iteration
- eBPF change → `go generate ./internal/loader/` then rebuild. Watch for verifier
  errors *at load time* (runtime), not compile time — they surface as
  `failed to load eBPF: ... load program: permission denied: <verifier msg>`.
- Parser change → `go test ./internal/tlsparse/` (no root needed).

### End-to-end verification (headless, no TTY)
```sh
sudo ./tlstat --dump 10s --interval 400ms &
sleep 2.5
( printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'; sleep 6 ) | \
  openssl s_client -connect example.com:443 -servername example.com -quiet >/dev/null
```
Expect a row: `openssl example.com TLS 1.3 TLS_AES_256_GCM_SHA384 … peek→ "GET / HTTP/1.1"`.
- TLS 1.2 cert: add `-tls1_2` and a host like `www.cloudflare.com`; expect
  `cert[CN=… SANs=… sig=…]`.
- Pre-existing: start `s_client` **before** tlstat; expect `pre-ex`, unknown
  crypto, bytes still counting.
- Clean shutdown: after quit, `sudo bpftool prog list` shows no tlstat programs.

`openssl s_client` is the best test client: long-lived, uses `libssl` (so it
exercises both the wire and uprobe paths), and `SSL_set_fd` for correlation.

### History / closed-connection verification
```sh
sudo ./tlstat --dump 10s --interval 400ms &
sleep 2.5
curl -s https://www.cloudflare.com -o /dev/null   # closes before next snapshot
```
Expect `[closed Ns ago]` rows persisting in the dump with plaintext totals +
tail. In the interactive TUI, `Tab` cycles to the Closed view.
- Retention cap: `--history 3`, fire 5 curls; last snapshot shows ≤3 closed.
- Map cleanup: `sudo bpftool map dump name ssl_stats | grep -c key` → 0 after
  all connections close (SSL_free uprobe cleans up).
curl works too but is short-lived, so its connection may close before a poll.

### Interactive TUI test
A pty harness (`pty.fork` + `TIOCSWINSZ` to set a window size, feed `q`) can
smoke-test rendering headlessly; capture is timing-sensitive because of
sudo-through-pty. Setting the winsize is required or `View()` stays on "starting…".

## 13. Environment requirements

- Linux kernel with BTF at `/sys/kernel/btf/vmlinux` (~5.8+ for ring buffers;
  developed on 7.0). CO-RE means the compiled object is portable across kernels.
- Root (CAP_BPF/CAP_SYS_ADMIN) at runtime.
- Build: clang/llvm, libbpf headers, Go ≥ 1.25 (cilium/ebpf v0.22 requirement).
- `libssl.so.3` present for cleartext capture (auto-detected; `--libssl` to override).
