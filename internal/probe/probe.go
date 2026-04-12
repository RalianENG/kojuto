//go:build linux

package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type connect_event -type file_event probe probe.c -- -I../../headers -O2 -g -D__TARGET_ARCH_x86

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	evtConnect  = 1
	evtSendto   = 2
	evtExecve   = 3
	evtOpenat   = 4
	evtRename   = 5
	evtPtrace   = 6
	evtMmap     = 7
	evtMprotect = 8
	evtUnlink   = 9
)

// openat flags (uapi/asm-generic/fcntl.h). We only format the subset the
// analyzer inspects — other bits are intentionally ignored.
const (
	oAccMode  = 0o3
	oWronly   = 0o1
	oRdwr     = 0o2
	oCreat    = 0o100
	oTrunc    = 0o1000
	oAppend   = 0o2000
	oCloexec  = 0o2000000
	oNonblock = 0o4000
)

// mmap/mprotect protection bits.
const (
	protRead  = 0x1
	protWrite = 0x2
	protExec  = 0x4
)

// mmap flags (subset used for MemFlags string formatting).
const (
	mapShared    = 0x01
	mapPrivate   = 0x02
	mapFixed     = 0x10
	mapAnonymous = 0x20
)

// Create→delete correlation for anti-forensics uses suspiciousUnlinkDirs
// (declared in strace_parse.go) to match both probe backends against the
// same prefix list.

// EBPFProbe monitors syscalls using eBPF kprobes and tracepoints.
type EBPFProbe struct {
	objs            *probeObjects
	links           []link.Link
	reader          *perf.Reader
	fileReader      *perf.Reader
	events          chan types.SyscallEvent
	done            chan struct{}
	closeOnce       sync.Once
	readerWg        sync.WaitGroup
	createdTmpMu    sync.Mutex
	createdTmpFiles map[string]bool
	LostSamples     uint64
	dropped         uint64 // events dropped due to full events channel
}

// NewEBPF creates a new eBPF-based probe.
//
// The events channel is 8192-buffered to match container_strace and to
// absorb install-phase bursts from pip/npm without blocking the BPF
// reader goroutines. If the buffer fills, readers drop events rather
// than block — a deadlocked reader would starve the main loop waiting
// on `docker exec` to return.
func NewEBPF() *EBPFProbe {
	return &EBPFProbe{
		events:          make(chan types.SyscallEvent, 8192),
		done:            make(chan struct{}),
		createdTmpFiles: make(map[string]bool),
	}
}

func (p *EBPFProbe) Start(targetPIDNS uint32) error {
	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	p.objs = &objs

	// Set target PID namespace inode.
	key := uint32(0)
	if err := objs.TargetPidns.Put(key, targetPIDNS); err != nil {
		return fmt.Errorf("setting target pidns: %w", err)
	}

	// Attach kprobes. Non-critical probes (sendto, execve, openat, rename)
	// are best-effort: if the kernel symbol doesn't exist, we skip it.
	kpConnect, err := link.Kprobe("__sys_connect", objs.KprobeConnect, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe connect: %w", err)
	}
	p.links = append(p.links, kpConnect)

	for _, attach := range []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"__sys_sendto", objs.KprobeSendto},
		{"__sys_sendmsg", objs.KprobeSendmsg},
		{"__sys_bind", objs.KprobeBind},
		{"__sys_listen", objs.KprobeListen},
		{"__sys_accept4", objs.KprobeAccept},
		{"do_sys_openat2", objs.KprobeOpenat},
		{"vfs_rename", objs.KprobeRename},
	} {
		if kp, kpErr := link.Kprobe(attach.sym, attach.prog, nil); kpErr == nil {
			p.links = append(p.links, kp)
		}
	}

	// Tracepoints for anti-evasion / memory-execution / anti-forensics
	// detection. Tracepoints are arch-independent and stable across
	// kernel versions, unlike the __sys_* kprobe symbols. Best-effort:
	// if a tracepoint is unavailable (ancient kernel, rare archs), skip.
	for _, tp := range []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_execve", objs.TpExecve},
		{"syscalls", "sys_enter_execveat", objs.TpExecveat},
		{"syscalls", "sys_enter_ptrace", objs.TpPtrace},
		{"syscalls", "sys_enter_mmap", objs.TpMmap},
		{"syscalls", "sys_enter_mprotect", objs.TpMprotect},
		{"syscalls", "sys_enter_unlink", objs.TpUnlink},
		{"syscalls", "sys_enter_unlinkat", objs.TpUnlinkat},
	} {
		if tl, tpErr := link.Tracepoint(tp.group, tp.name, tp.prog, nil); tpErr == nil {
			p.links = append(p.links, tl)
		} else {
			fmt.Fprintf(os.Stderr, "[!] eBPF: tracepoint attach failed for %s/%s: %v\n", tp.group, tp.name, tpErr)
		}
	}

	// Open perf event readers with large buffers.
	pageSize := os.Getpagesize()
	rd, err := perf.NewReader(objs.Events, pageSize*512)
	if err != nil {
		return fmt.Errorf("creating network perf reader: %w", err)
	}
	p.reader = rd

	fileRd, err := perf.NewReader(objs.FileEvents, pageSize*256)
	if err != nil {
		return fmt.Errorf("creating file perf reader: %w", err)
	}
	p.fileReader = fileRd

	p.readerWg.Add(2)
	go p.readNetworkLoop()
	go p.readFileLoop()
	return nil
}

func (p *EBPFProbe) readNetworkLoop() {
	defer p.readerWg.Done()
	for {
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		if record.LostSamples > 0 {
			p.LostSamples += record.LostSamples
			continue
		}

		var raw probeConnectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		var commBytes [16]byte
		for i, c := range raw.Comm {
			commBytes[i] = byte(c)
		}

		// Determine syscall type: connect events come from kprobe_connect,
		// sendto from kprobe_sendto. Both use the same struct, so we infer
		// from context. Since we can't distinguish in the perf buffer,
		// we label all network events as "connect" for now.
		// The analyzer treats connect and sendto identically.
		evt := types.SyscallEvent{
			Timestamp: time.Now().UTC(),
			PID:       raw.Pid,
			Comm:      nullTermString(commBytes[:]),
			Syscall:   types.EventConnect,
			Family:    raw.Family,
			DstPort:   raw.Dport,
			DstAddr:   formatAddr(raw.Family, raw.Daddr),
		}

		select {
		case p.events <- evt:
		case <-p.done:
			return
		default:
			// Buffer full — drop rather than block. The BPF reader must
			// not stall: if it does, the perf buffer overflows and the
			// analyzer reports `inconclusive`.
			p.dropped++
		}
	}
}

func (p *EBPFProbe) readFileLoop() {
	defer p.readerWg.Done()
	for {
		record, err := p.fileReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		if record.LostSamples > 0 {
			p.LostSamples += record.LostSamples
			continue
		}

		var raw probeFileEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		var pathBytes [128]byte
		for i, c := range raw.Path {
			pathBytes[i] = byte(c)
		}
		path := nullTermString(pathBytes[:])

		var path2Bytes [128]byte
		for i, c := range raw.Path2 {
			path2Bytes[i] = byte(c)
		}
		path2 := nullTermString(path2Bytes[:])

		evt := types.SyscallEvent{
			Timestamp: time.Now().UTC(),
			PID:       raw.Pid,
		}

		switch raw.EventType {
		case evtExecve:
			evt.Syscall = types.EventExecve
			evt.Comm = path
		case evtOpenat:
			evt.Syscall = types.EventOpenat
			evt.FilePath = path
			evt.OpenFlags = formatOpenFlags(raw.Extra1)
			// Track create→delete candidates for anti-forensics correlation.
			if raw.Extra1&oCreat != 0 && isSuspiciousTmpPath(path) {
				p.createdTmpMu.Lock()
				p.createdTmpFiles[path] = true
				p.createdTmpMu.Unlock()
			}
		case evtRename:
			evt.Syscall = types.EventRename
			evt.SrcPath = path
			evt.DstPath = path2
		case evtPtrace:
			evt.Syscall = types.EventPtrace
			evt.Comm = "ptrace(PTRACE_TRACEME)"
		case evtMmap:
			evt.Syscall = types.EventMmap
			evt.MemProt = formatProt(raw.Extra1)
			evt.MemFlags = formatMmapFlags(raw.Extra2)
		case evtMprotect:
			evt.Syscall = types.EventMprotect
			evt.MemProt = formatProt(raw.Extra1)
		case evtUnlink:
			// Only emit if the path was created during this scan under a
			// suspicious directory — matches strace-mode behavior.
			p.createdTmpMu.Lock()
			created := p.createdTmpFiles[path]
			p.createdTmpMu.Unlock()
			if !created {
				continue
			}
			evt.Syscall = types.EventUnlink
			evt.FilePath = path
		default:
			continue
		}

		select {
		case p.events <- evt:
		case <-p.done:
			return
		default:
			p.dropped++
		}
	}
}

func (p *EBPFProbe) Events() <-chan types.SyscallEvent {
	return p.events
}

func (p *EBPFProbe) Close() error {
	p.closeOnce.Do(func() {
		// Signal reader goroutines to stop on their next iteration.
		close(p.done)
		// Closing the perf readers unblocks any in-flight Read() calls
		// with perf.ErrClosed so the goroutines can exit.
		if p.reader != nil {
			p.reader.Close()
		}
		if p.fileReader != nil {
			p.fileReader.Close()
		}
		// Wait for both reader goroutines to finish before closing the
		// events channel — closing while they may still be sending would
		// panic. After this, the consumer's `for evt := range Events()`
		// can drain remaining buffered events and exit cleanly.
		p.readerWg.Wait()
		close(p.events)
		// Detach probes and free BPF objects last.
		for _, l := range p.links {
			l.Close()
		}
		if p.objs != nil {
			p.objs.Close()
		}
	})
	return nil
}

func (p *EBPFProbe) Method() string {
	return "ebpf"
}

// Dropped returns events discarded because the events channel was full.
func (p *EBPFProbe) Dropped() uint64 {
	return p.dropped
}

// isSuspiciousTmpPath reports whether path lives under a directory where
// the create→execute→delete anti-forensics pattern is monitored. Mirrors
// suspiciousUnlinkDirs in strace_parse.go.
func isSuspiciousTmpPath(path string) bool {
	for _, dir := range suspiciousUnlinkDirs {
		if len(path) >= len(dir) && path[:len(dir)] == dir {
			return true
		}
	}
	return false
}

// formatOpenFlags renders open_how.flags into the strace-style string the
// analyzer's classifyOpenat substring-checks ("O_WRONLY", "O_RDWR", "O_CREAT").
func formatOpenFlags(flags uint32) string {
	var parts []string
	switch flags & oAccMode {
	case oWronly:
		parts = append(parts, "O_WRONLY")
	case oRdwr:
		parts = append(parts, "O_RDWR")
	default:
		parts = append(parts, "O_RDONLY")
	}
	if flags&oCreat != 0 {
		parts = append(parts, "O_CREAT")
	}
	if flags&oTrunc != 0 {
		parts = append(parts, "O_TRUNC")
	}
	if flags&oAppend != 0 {
		parts = append(parts, "O_APPEND")
	}
	if flags&oNonblock != 0 {
		parts = append(parts, "O_NONBLOCK")
	}
	if flags&oCloexec != 0 {
		parts = append(parts, "O_CLOEXEC")
	}
	return strings.Join(parts, "|")
}

// formatProt renders mmap/mprotect prot bits into strace-style
// "PROT_READ|PROT_WRITE|PROT_EXEC". The analyzer substring-matches
// on "PROT_WRITE" and "PROT_EXEC" to classify shellcode injection.
func formatProt(prot uint32) string {
	var parts []string
	if prot&protRead != 0 {
		parts = append(parts, "PROT_READ")
	}
	if prot&protWrite != 0 {
		parts = append(parts, "PROT_WRITE")
	}
	if prot&protExec != 0 {
		parts = append(parts, "PROT_EXEC")
	}
	if len(parts) == 0 {
		return "PROT_NONE"
	}
	return strings.Join(parts, "|")
}

// formatMmapFlags renders mmap flags into strace-style
// "MAP_PRIVATE|MAP_ANONYMOUS" for the analyzer's diagnostic string.
func formatMmapFlags(flags uint32) string {
	var parts []string
	if flags&mapShared != 0 {
		parts = append(parts, "MAP_SHARED")
	}
	if flags&mapPrivate != 0 {
		parts = append(parts, "MAP_PRIVATE")
	}
	if flags&mapFixed != 0 {
		parts = append(parts, "MAP_FIXED")
	}
	if flags&mapAnonymous != 0 {
		parts = append(parts, "MAP_ANONYMOUS")
	}
	return strings.Join(parts, "|")
}

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func formatAddr(family uint16, addr [16]uint8) string {
	if family == 2 { // AF_INET
		return net.IP(addr[:4]).String()
	}
	return net.IP(addr[:]).String()
}
