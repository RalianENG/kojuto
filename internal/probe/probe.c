//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET  2
#define AF_INET6 10

struct connect_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 dport;
    __u8  daddr[16]; // IPv4 uses first 4 bytes, IPv6 uses all 16
    char  comm[16];
};

// Perf event array for sending events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Map to store target container PID namespace inode for filtering.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pidns SEC(".maps");

// Get the PID namespace inode of the current task.
static __always_inline __u32 get_pidns_inum(struct task_struct *task) {
    struct nsproxy *nsproxy;
    struct pid_namespace *pidns;
    unsigned int inum;

    nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return 0;

    pidns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (!pidns)
        return 0;

    inum = BPF_CORE_READ(pidns, ns.inum);
    return inum;
}

SEC("kprobe/__sys_connect")
int kprobe_connect(struct pt_regs *ctx) {
    // Filter by target PID namespace
    __u32 key = 0;
    __u32 *target_inum = bpf_map_lookup_elem(&target_pidns, &key);
    if (!target_inum || *target_inum == 0)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 current_inum = get_pidns_inum(task);
    if (current_inum != *target_inum)
        return 0;

    // Read sockaddr from second argument
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!addr)
        return 0;

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct connect_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.family = family;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &addr4->sin_port);
        bpf_probe_read_user(&evt.daddr, 4, &addr4->sin_addr);
    } else { // AF_INET6
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &addr6->sin6_port);
        bpf_probe_read_user(&evt.daddr, 16, &addr6->sin6_addr);
    }

    // Convert port from network byte order
    evt.dport = __builtin_bswap16(evt.dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
