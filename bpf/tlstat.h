/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Shared layout between the eBPF programs and the Go userspace.
 * All structs are __packed so Go can parse them at fixed byte offsets
 * without worrying about C alignment padding. x86-64 is little-endian. */
#ifndef __TLSTAT_H
#define __TLSTAT_H

#define TASK_COMM_LEN 16
#define WIRE_CAP 1024 /* bytes of wire data captured per handshake event */
#define DATA_CAP 1024 /* bytes of plaintext captured per uprobe event   */

#define MAX_WIRE_EVENTS 16 /* wire chunks emitted per direction per socket */
/* Plaintext samples are emitted continuously (no per-SSL cap): userspace keeps
 * the head (first chunk) plus a rolling tail of the last N bytes per direction. */

/* ring buffer event discriminator (first byte of every event) */
enum event_type {
	EVENT_WIRE = 1,  /* raw TLS records off the wire, for handshake parsing */
	EVENT_DATA = 2,  /* plaintext captured from the TLS library uprobe      */
	EVENT_CLOSE = 3, /* SSL session freed: final plaintext byte totals      */
};

/* direction */
enum dir {
	DIR_OUT = 1, /* egress / SSL_write / client->server */
	DIR_IN = 2,  /* ingress / SSL_read  / server->client */
};

/* Per-socket flow state, keyed by the kernel `struct sock *` pointer.
 * Userspace polls this map to discover connections (new and pre-existing)
 * and to read live byte counters. */
struct flow {
	__u64 tx; /* bytes sent on the wire   */
	__u64 rx; /* bytes received on the wire */
	__u32 pid;
	__u32 saddr[4]; /* network byte order; v4 in [0] */
	__u32 daddr[4];
	__u16 sport; /* host order */
	__u16 dport; /* host order */
	__u8 is_ipv6;
	__u8 direction; /* 0 unknown, DIR_OUT client, DIR_IN server */
	__u8 is_tls;
	__u8 closed;
	__u8 wire_out; /* wire events emitted so far, egress  */
	__u8 wire_in;  /* wire events emitted so far, ingress */
	char comm[TASK_COMM_LEN];
} __attribute__((packed));

/* Per-SSL plaintext state, keyed by the OpenSSL `SSL *` pointer. */
struct ssl_stat {
	__u64 ptx; /* plaintext bytes written (SSL_write) */
	__u64 prx; /* plaintext bytes read (SSL_read)     */
	__u32 pid;
	__s32 fd; /* resolved from SSL_set_fd, else -1     */
} __attribute__((packed));

struct wire_event {
	__u8 type; /* EVENT_WIRE */
	__u8 direction;
	__u16 len; /* captured bytes in data[] */
	__u64 sk;  /* struct sock * key into `flows` */
	__u8 data[WIRE_CAP];
} __attribute__((packed));

/* Emitted from SSL_free with the session's final plaintext byte totals, so
 * userspace can attribute plaintext to short-lived connections that close
 * before the ssl_stats map is next polled. */
struct close_event {
	__u8 type; /* EVENT_CLOSE */
	__u8 _pad[3];
	__u32 pid;
	__s32 fd;
	__u64 ssl;
	__u64 ptx;
	__u64 prx;
} __attribute__((packed));

struct data_event {
	__u8 type; /* EVENT_DATA */
	__u8 direction;
	__u16 len;
	__u32 pid;
	__u32 tid;
	__s32 fd;  /* -1 if unknown */
	__u64 ssl; /* SSL * pointer  */
	__u8 data[DATA_CAP];
} __attribute__((packed));

/* scratch entries for entry->exit probe pairing, keyed by pid_tgid */
struct recv_ctx {
	__u64 sk;
	__u64 base; /* user buffer that will receive data */
};

struct ssl_ctx {
	__u64 ssl;
	__u64 buf;
};

#endif /* __TLSTAT_H */
