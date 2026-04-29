// miku-shield Phase 2 — LSM-based anti-Frida detection mitigation.
//
// Two LSM hooks run alongside the syscall trace:
//
//   lsm/file_open     — refuse open() of paths that match the
//                       shield_block_paths map  → returns -EACCES.
//                       Used to hide /data/local/tmp/frida-server,
//                       /data/local/tmp/.miku-srv, ...
//
//   lsm/socket_connect — refuse connect() to ports that match the
//                        shield_block_ports map → returns -ECONNREFUSED.
//                        Used to hide ports 27042, 27043, 6699.
//
// Both checks are scoped to a single uid (the target package) provided
// through the .rodata constant TARGET_UID at load time.  Other apps
// stay unaffected — important so mitigation does not impact unrelated
// Android system services.
//
// The BPF program is intentionally tiny: no per-cpu state, no
// ring-buffer, no string parsing inside the program.  Path matching
// is done by hashing a fixed prefix of the path bytes and comparing
// against keys the userspace loader writes into shield_block_paths.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// ── tunable: target uid ───────────────────────────────────────────────
//
// Userspace patches this constant via skel->rodata before loading.
// uid==0 means "any uid" — the program will run for every process,
// usually only useful for debugging.
volatile const __u32 TARGET_UID = 0;

// ── path-match key ────────────────────────────────────────────────────
//
// The userspace agent computes a 240-byte zero-padded prefix of every
// path it wants to block and uses that as the key.  We pick 240 to give
// some headroom under 256 (BPF stack limit per program is 512 bytes,
// shared between locals).
#define PATH_KEY_LEN 240

struct path_key {
	char buf[PATH_KEY_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct path_key);
	__type(value, __u8);    // value is unused; the map is a set
} shield_block_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);     // port (network byte order)
	__type(value, __u8);
} shield_block_ports SEC(".maps");

// Per-cpu scratch buffer to read the path into without touching the
// 512-byte stack limit for every call.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_key);
} shield_scratch SEC(".maps");

// stats keeps a tiny counter set so userspace can confirm the program
// was actually triggered without enabling bpf_printk.
struct shield_stats {
	__u64 file_open_checked;
	__u64 file_open_blocked;
	__u64 sock_connect_checked;
	__u64 sock_connect_blocked;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shield_stats);
} shield_stats_map SEC(".maps");

static __always_inline struct shield_stats *shield_stats_get(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&shield_stats_map, &z);
}

static __always_inline int uid_matches(void)
{
	__u64 ug = bpf_get_current_uid_gid();
	__u32 uid = (__u32)(ug & 0xffffffff);
	if (TARGET_UID == 0)
		return 1;
	return uid == TARGET_UID;
}

// LSM file_open hook ---------------------------------------------------
//
// kernel: int file_open(struct file *file)
SEC("lsm/file_open")
int BPF_PROG(shield_file_open, struct file *file)
{
	struct shield_stats *st = shield_stats_get();
	if (!uid_matches())
		return 0;
	if (st)
		__sync_fetch_and_add(&st->file_open_checked, 1);

	__u32 z = 0;
	struct path_key *scratch = bpf_map_lookup_elem(&shield_scratch, &z);
	if (!scratch)
		return 0;
	// zero the buffer so map lookup has a deterministic key.
	for (int i = 0; i < PATH_KEY_LEN; i++)
		scratch->buf[i] = 0;

	struct path p = BPF_CORE_READ(file, f_path);
	long n = bpf_d_path(&p, scratch->buf, PATH_KEY_LEN);
	if (n <= 0)
		return 0;

	__u8 *hit = bpf_map_lookup_elem(&shield_block_paths, scratch);
	if (hit) {
		if (st)
			__sync_fetch_and_add(&st->file_open_blocked, 1);
		return -13; // -EACCES
	}
	return 0;
}

// LSM socket_connect hook ---------------------------------------------
//
// kernel: int socket_connect(struct socket *sock, struct sockaddr *addr, int addrlen)
SEC("lsm/socket_connect")
int BPF_PROG(shield_socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen)
{
	struct shield_stats *st = shield_stats_get();
	if (!uid_matches())
		return 0;
	if (st)
		__sync_fetch_and_add(&st->sock_connect_checked, 1);

	if (!addr || addrlen < (int)sizeof(struct sockaddr))
		return 0;
	__u16 family = BPF_CORE_READ(addr, sa_family);
	__u16 port_be = 0;
	if (family == 2 /* AF_INET */) {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		port_be = BPF_CORE_READ(in, sin_port);
	} else if (family == 10 /* AF_INET6 */) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
		port_be = BPF_CORE_READ(in6, sin6_port);
	} else {
		return 0;
	}
	__u16 port = (__u16)((port_be >> 8) | (port_be << 8));

	__u8 *hit = bpf_map_lookup_elem(&shield_block_ports, &port);
	if (hit) {
		if (st)
			__sync_fetch_and_add(&st->sock_connect_blocked, 1);
		return -111; // -ECONNREFUSED
	}
	return 0;
}
