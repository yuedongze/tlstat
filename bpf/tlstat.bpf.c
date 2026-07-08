// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tlstat.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Anchor these types in BTF so bpf2go emits Go bindings for them. */
const struct flow *_unused_flow __attribute__((unused));
const struct ssl_stat *_unused_ssl_stat __attribute__((unused));
const struct wire_event *_unused_wire_event __attribute__((unused));
const struct data_event *_unused_data_event __attribute__((unused));

/* ----------------------------- maps ----------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* struct sock * */
	__type(value, struct flow);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* SSL * */
	__type(value, struct ssl_stat);
} ssl_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* SSL * */
	__type(value, __s32); /* fd */
} ssl_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); /* pid_tgid */
	__type(value, struct recv_ctx);
} recv_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); /* pid_tgid */
	__type(value, struct ssl_ctx);
} ssl_ctxs SEC(".maps");

/* ------------------------- helpers ------------------------------------ */

/* Pull the base user pointer out of a msghdr's iov_iter. Handles the two
 * common iterator kinds produced by userspace send/recv paths. */
static __always_inline void *iter_base(struct iov_iter *iter)
{
	__u8 t = BPF_CORE_READ(iter, iter_type);
	if (t == ITER_UBUF)
		return BPF_CORE_READ(iter, ubuf);
	if (t == ITER_IOVEC) {
		const struct iovec *iov = BPF_CORE_READ(iter, __iov);
		return BPF_CORE_READ(iov, iov_base);
	}
	return NULL;
}

/* Does the buffer start with something that looks like a TLS record? */
static __always_inline int looks_like_tls(const __u8 *hdr)
{
	__u8 ct = hdr[0];
	/* change_cipher_spec(20) alert(21) handshake(22) application_data(23) */
	if (ct < 20 || ct > 23)
		return 0;
	if (hdr[1] != 0x03) /* major version */
		return 0;
	if (hdr[2] > 0x04) /* minor: SSL3.0(0)..TLS1.3(4) */
		return 0;
	return 1;
}

/* Fill the 4-tuple of a flow entry from a struct sock. */
static __always_inline void read_tuple(struct sock *sk, struct flow *f)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	f->sport = BPF_CORE_READ(sk, __sk_common.skc_num); /* host order */
	f->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET6) {
		f->is_ipv6 = 1;
		BPF_CORE_READ_INTO(&f->saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&f->daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	} else {
		f->is_ipv6 = 0;
		f->saddr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		f->daddr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	}
}

/* Get or lazily create the flow entry for a socket. Runs in process context
 * (from the send/recv kprobes), so it also backfills identity for entries that
 * were first created empty by the connection-state tracepoint (softirq). */
static __always_inline struct flow *flow_get(struct sock *sk)
{
	__u64 key = (__u64)sk;
	struct flow *f = bpf_map_lookup_elem(&flows, &key);
	if (!f) {
		struct flow zero = {};
		bpf_map_update_elem(&flows, &key, &zero, BPF_ANY);
		f = bpf_map_lookup_elem(&flows, &key);
		if (!f)
			return NULL;
	}
	if (f->pid == 0) {
		f->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&f->comm, sizeof(f->comm));
		read_tuple(sk, f);
	}
	return f;
}

/* Emit up to WIRE_CAP bytes of a wire buffer for handshake reassembly. The
 * first chunk in a direction must look like a TLS record (so we don't slurp
 * plain HTTP); once a direction is "armed", every following chunk is captured
 * unconditionally — TLS record headers and bodies routinely arrive in separate
 * syscalls, so continuation chunks won't start with a record header. */
static __always_inline void capture_wire(struct sock *sk, struct flow *f,
					 void *buf, __u64 n, __u8 dir)
{
	if (!buf || n < 1)
		return;

	__u8 *cnt = (dir == DIR_OUT) ? &f->wire_out : &f->wire_in;
	if (*cnt >= MAX_WIRE_EVENTS)
		return;

	if (*cnt == 0) {
		if (n < 5)
			return;
		__u8 hdr[5];
		if (bpf_probe_read_user(hdr, sizeof(hdr), buf))
			return;
		if (!looks_like_tls(hdr))
			return;
		f->is_tls = 1;
	}

	struct wire_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->type = EVENT_WIRE;
	e->direction = dir;
	e->sk = (__u64)sk;
	__u32 cap = n;
	if (cap > WIRE_CAP - 1)
		cap = WIRE_CAP - 1;
	cap &= (WIRE_CAP - 1); /* redundant clamp the verifier can prove */
	if (bpf_probe_read_user(e->data, cap, buf)) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	e->len = cap;
	(*cnt)++;
	bpf_ringbuf_submit(e, 0);
}

/* --------------------- wire: byte counts + capture -------------------- */

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(k_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct flow *f = flow_get(sk);
	if (!f)
		return 0;
	f->tx += size;

	void *base = iter_base(&msg->msg_iter);
	capture_wire(sk, f, base, size, DIR_OUT);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(k_tcp_recvmsg, struct sock *sk, struct msghdr *msg)
{
	struct recv_ctx rc = {};
	rc.sk = (__u64)sk;
	rc.base = (__u64)iter_base(&msg->msg_iter);
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&recv_ctxs, &id, &rc, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kr_tcp_recvmsg, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct recv_ctx *rc = bpf_map_lookup_elem(&recv_ctxs, &id);
	if (!rc)
		return 0;
	struct sock *sk = (struct sock *)rc->sk;
	void *base = (void *)rc->base;
	bpf_map_delete_elem(&recv_ctxs, &id);

	if (ret <= 0 || !sk)
		return 0;

	struct flow *f = flow_get(sk);
	if (!f)
		return 0;
	f->rx += ret;
	capture_wire(sk, f, base, ret, DIR_IN);
	return 0;
}

/* -------------------- connection lifecycle / direction ---------------- */

SEC("tp/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	__u64 key = (__u64)ctx->skaddr;

	if (ctx->newstate == TCP_ESTABLISHED) {
		struct flow *f = bpf_map_lookup_elem(&flows, &key);
		struct flow zero = {};
		if (!f) {
			bpf_map_update_elem(&flows, &key, &zero, BPF_NOEXIST);
			f = bpf_map_lookup_elem(&flows, &key);
			if (!f)
				return 0;
		}
		/* SYN_SENT -> active connect (client); SYN_RECV -> passive (server).
		 * The 4-tuple and identity are filled by the send/recv kprobes (process
		 * context); connections that never transfer data are filtered out in
		 * userspace via Conn.HasEndpoint. */
		f->direction = (ctx->oldstate == TCP_SYN_RECV) ? DIR_IN : DIR_OUT;
	} else if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_CLOSE_WAIT) {
		struct flow *f = bpf_map_lookup_elem(&flows, &key);
		if (f)
			f->closed = 1;
	}
	return 0;
}

/* --------------------- cleartext: OpenSSL uprobes --------------------- */

static __always_inline struct ssl_stat *ssl_stat_get(__u64 ssl)
{
	struct ssl_stat *s = bpf_map_lookup_elem(&ssl_stats, &ssl);
	if (s)
		return s;
	struct ssl_stat zero = {};
	zero.pid = bpf_get_current_pid_tgid() >> 32;
	zero.fd = -1;
	__s32 *fd = bpf_map_lookup_elem(&ssl_fds, &ssl);
	if (fd)
		zero.fd = *fd;
	bpf_map_update_elem(&ssl_stats, &ssl, &zero, BPF_ANY);
	return bpf_map_lookup_elem(&ssl_stats, &ssl);
}

static __always_inline void emit_plaintext(__u64 ssl, void *buf, __u64 n,
					   __u8 dir)
{
	if (!buf || n == 0)
		return;
	struct ssl_stat *s = ssl_stat_get(ssl);
	if (!s)
		return;
	if (dir == DIR_OUT)
		s->ptx += n;
	else
		s->prx += n;

	__u16 *emit = (dir == DIR_OUT) ? &s->out_emit : &s->in_emit;
	if (*emit >= MAX_DATA_EVENTS)
		return;

	struct data_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__u64 id = bpf_get_current_pid_tgid();
	e->type = EVENT_DATA;
	e->direction = dir;
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->fd = s->fd;
	e->ssl = ssl;
	__u32 cap = n;
	if (cap > DATA_CAP - 1)
		cap = DATA_CAP - 1;
	cap &= (DATA_CAP - 1);
	if (bpf_probe_read_user(e->data, cap, buf)) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	e->len = cap;
	(*emit)++;
	bpf_ringbuf_submit(e, 0);
}

/* int SSL_set_fd(SSL *ssl, int fd) — build the SSL*->fd map */
SEC("uprobe/SSL_set_fd")
int BPF_UPROBE(u_ssl_set_fd, void *ssl, int fd)
{
	__u64 key = (__u64)ssl;
	__s32 v = fd;
	bpf_map_update_elem(&ssl_fds, &key, &v, BPF_ANY);
	return 0;
}

/* int SSL_write(SSL *ssl, const void *buf, int num) */
SEC("uprobe/SSL_write")
int BPF_UPROBE(u_ssl_write, void *ssl, void *buf, int num)
{
	if (num > 0)
		emit_plaintext((__u64)ssl, buf, num, DIR_OUT);
	return 0;
}

/* int SSL_read(SSL *ssl, void *buf, int num) — data is valid on return */
SEC("uprobe/SSL_read")
int BPF_UPROBE(u_ssl_read, void *ssl, void *buf)
{
	struct ssl_ctx c = {};
	c.ssl = (__u64)ssl;
	c.buf = (__u64)buf;
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&ssl_ctxs, &id, &c, BPF_ANY);
	return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(ur_ssl_read, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx *c = bpf_map_lookup_elem(&ssl_ctxs, &id);
	if (!c)
		return 0;
	__u64 ssl = c->ssl;
	void *buf = (void *)c->buf;
	bpf_map_delete_elem(&ssl_ctxs, &id);
	if (ret > 0)
		emit_plaintext(ssl, buf, ret, DIR_IN);
	return 0;
}
