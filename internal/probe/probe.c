//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET  2
#define AF_INET6 10

#define EVT_CONNECT 1
#define EVT_SENDTO  2
#define EVT_EXECVE  3
#define EVT_OPENAT  4
#define EVT_RENAME  5

// Network event (connect, sendto).
struct connect_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u16 dport;
    __u8  daddr[16];
    char  comm[16];
};

// File/process event (execve, openat, rename).
struct file_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  event_type;
    __u8  _pad[3];
    char  path[128];
    char  path2[128]; // dst_path for rename, unused for others
};

// Perf event arrays for sending events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} file_events SEC(".maps");

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

// Check if the current task belongs to the target PID namespace.
static __always_inline bool is_target_ns(void) {
    __u32 key = 0;
    __u32 *target_inum = bpf_map_lookup_elem(&target_pidns, &key);
    if (!target_inum || *target_inum == 0)
        return false;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return get_pidns_inum(task) == *target_inum;
}

// Parse sockaddr and emit a connect_event.
static __always_inline int handle_sockaddr(struct pt_regs *ctx, struct sockaddr *addr) {
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
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &addr6->sin6_port);
        bpf_probe_read_user(&evt.daddr, 16, &addr6->sin6_addr);
    }

    evt.dport = __builtin_bswap16(evt.dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("kprobe/__sys_connect")
int kprobe_connect(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    return handle_sockaddr(ctx, addr);
}

SEC("kprobe/__sys_sendto")
int kprobe_sendto(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;
    // sendto(fd, buf, len, flags, dest_addr, addrlen)
    // dest_addr is the 5th argument (index 4).
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
    return handle_sockaddr(ctx, addr);
}

SEC("kprobe/do_execveat_common")
int kprobe_execve(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;

    // do_execveat_common(int fd, struct filename *filename, ...)
    // The filename struct contains the path string.
    struct filename *fname = (struct filename *)PT_REGS_PARM2(ctx);
    if (!fname)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_EXECVE;

    const char *name_ptr;
    bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &fname->name);
    bpf_probe_read_kernel_str(&evt.path, sizeof(evt.path), name_ptr);

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("kprobe/do_sys_openat2")
int kprobe_openat(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;

    // do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    if (!filename)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_OPENAT;

    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), filename);

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("kprobe/vfs_rename")
int kprobe_rename(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;

    // vfs_rename signature varies by kernel version.
    // On 5.12+: vfs_rename(struct renamedata *rd)
    // We use BPF_CORE_READ to access the dentry names portably.
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    if (!rd)
        return 0;

    struct dentry *old_dentry;
    struct dentry *new_dentry;
    bpf_probe_read_kernel(&old_dentry, sizeof(old_dentry), &rd->old_dentry);
    bpf_probe_read_kernel(&new_dentry, sizeof(new_dentry), &rd->new_dentry);

    if (!old_dentry || !new_dentry)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_RENAME;

    // Read dentry names (basename only — full path reconstruction is
    // expensive in BPF; the analyzer uses basename matching anyway).
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &old_dentry->d_name);
    bpf_probe_read_kernel_str(&evt.path, sizeof(evt.path), d_name.name);

    bpf_probe_read_kernel(&d_name, sizeof(d_name), &new_dentry->d_name);
    bpf_probe_read_kernel_str(&evt.path2, sizeof(evt.path2), d_name.name);

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "MIT";