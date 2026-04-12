//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_INET  2
#define AF_INET6 10

#define EVT_CONNECT  1
#define EVT_SENDTO   2
#define EVT_EXECVE   3
#define EVT_OPENAT   4
#define EVT_RENAME   5
#define EVT_PTRACE   6
#define EVT_MMAP     7
#define EVT_MPROTECT 8
#define EVT_UNLINK   9

// ptrace request codes (uapi/linux/ptrace.h).
#define PTRACE_TRACEME 0

// mmap/mprotect prot flags (asm-generic/mman-common.h).
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

// mmap flags (asm-generic/mman.h).
#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

// unlinkat flag AT_REMOVEDIR — rmdir, not file deletion.
#define AT_REMOVEDIR 0x200

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

// File/process event (execve, openat, rename, ptrace, mmap, mprotect, unlink).
//
// Field overloading by event_type:
//   EVT_EXECVE   : path = binary path
//   EVT_OPENAT   : path = filename,     extra1 = open_how->flags (lo 32 bits)
//   EVT_RENAME   : path = old basename, path2 = new basename
//   EVT_PTRACE   : (no extra data — filtered to PTRACE_TRACEME in BPF)
//   EVT_MMAP     : extra1 = prot,       extra2 = flags
//   EVT_MPROTECT : extra1 = prot
//   EVT_UNLINK   : path = filename
struct file_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  event_type;
    __u8  _pad[3];
    __u32 extra1;
    __u32 extra2;
    char  path[128];
    char  path2[128];
};

// Force BTF retention of the event structs so bpf2go's `-type` flag can
// locate them. Without this, clang with -O2 dedupes stack-only types out
// of the BTF and bpf2go fails with "collect C types: not found".
struct connect_event *_btf_keep_connect_event __attribute__((used));
struct file_event    *_btf_keep_file_event    __attribute__((used));

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
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM5(ctx);
    return handle_sockaddr(ctx, addr);
}

SEC("kprobe/__sys_sendmsg")
int kprobe_sendmsg(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;
    // sendmsg(fd, struct msghdr *msg, flags).
    // Extract destination address from msghdr->msg_name.
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg)
        return 0;

    struct sockaddr *addr = NULL;
    bpf_probe_read_user(&addr, sizeof(addr), &msg->msg_name);
    return handle_sockaddr(ctx, addr);
}

SEC("kprobe/__sys_bind")
int kprobe_bind(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    return handle_sockaddr(ctx, addr);
}

SEC("kprobe/__sys_listen")
int kprobe_listen(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;

    // listen(fd, backlog) has no sockaddr. Emit a minimal event
    // so the analyzer can flag it as a backdoor indicator.
    struct connect_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("kprobe/__sys_accept4")
int kprobe_accept(struct pt_regs *ctx) {
    if (!is_target_ns())
        return 0;

    struct connect_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
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

    // Read open_how->flags so the analyzer can distinguish O_RDONLY from
    // O_WRONLY/O_CREAT (persistence writes to shell startup files, and
    // anti-forensics create→delete correlation on /tmp payloads).
    struct open_how *how = (struct open_how *)PT_REGS_PARM3(ctx);
    if (how) {
        __u64 oflags = 0;
        bpf_probe_read_kernel(&oflags, sizeof(oflags), &how->flags);
        evt.extra1 = (__u32)oflags;
    }

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

// Tracepoint context for syscalls/sys_enter_*. args[0..5] hold the
// syscall's first six arguments as unsigned longs.
struct sys_enter_ctx {
    __u64 pad;
    __s32 id;
    __u32 _pad2;
    __u64 args[6];
};

// ptrace(request, pid, addr, data). PTRACE_TRACEME is the anti-debugging
// canary: the child calls it to confirm it is not already being traced.
// Any PTRACE_TRACEME during install/import is treated as evasion.
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct sys_enter_ctx *ctx) {
    if (!is_target_ns())
        return 0;

    __u64 request = ctx->args[0];
    if (request != PTRACE_TRACEME)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_PTRACE;

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// mmap(addr, len, prot, flags, fd, offset). Flag simultaneous PROT_WRITE+
// PROT_EXEC on anonymous/private mappings — the shellcode-injection pattern.
// V8 JIT uses W^X (never simultaneous RWX), so this is a reliable signal.
SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap(struct sys_enter_ctx *ctx) {
    if (!is_target_ns())
        return 0;

    __u64 prot = ctx->args[2];
    __u64 flags = ctx->args[3];

    if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
        return 0;

    // Require MAP_ANONYMOUS or MAP_PRIVATE to exclude file-backed mappings
    // (rare but possible for legitimate shared libraries with exotic flags).
    if (!(flags & MAP_ANONYMOUS))
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_MMAP;
    evt.extra1 = (__u32)prot;
    evt.extra2 = (__u32)flags;

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// mprotect(addr, len, prot). Flag transitions to simultaneous WRITE+EXEC —
// the classic "modify code in place" shellcode injection technique.
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_mprotect(struct sys_enter_ctx *ctx) {
    if (!is_target_ns())
        return 0;

    __u64 prot = ctx->args[2];
    if (!(prot & PROT_WRITE) || !(prot & PROT_EXEC))
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_MPROTECT;
    evt.extra1 = (__u32)prot;

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// unlink(pathname). Emitted unconditionally; userspace correlates with
// prior openat(O_CREAT) in /tmp etc. to detect the create→execute→delete
// anti-forensics pattern.
SEC("tracepoint/syscalls/sys_enter_unlink")
int tp_unlink(struct sys_enter_ctx *ctx) {
    if (!is_target_ns())
        return 0;

    const char *filename = (const char *)ctx->args[0];
    if (!filename)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_UNLINK;

    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), filename);

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// unlinkat(dfd, pathname, flags). Skip directory removal (AT_REMOVEDIR)
// since we only care about file deletion for anti-forensics.
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct sys_enter_ctx *ctx) {
    if (!is_target_ns())
        return 0;

    __u64 flags = ctx->args[2];
    if (flags & AT_REMOVEDIR)
        return 0;

    const char *filename = (const char *)ctx->args[1];
    if (!filename)
        return 0;

    struct file_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.event_type = EVT_UNLINK;

    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), filename);

    bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// "Dual MIT/GPL" lets the verifier use GPL-restricted helpers
// (bpf_ktime_get_ns, bpf_perf_event_output) while keeping the source
// licensed under MIT alongside the rest of the project.
char LICENSE[] SEC("license") = "Dual MIT/GPL";