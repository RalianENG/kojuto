//go:build linux

package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type connect_event -type file_event probe probe.c -- -I../../headers -O2 -g

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/RalianENG/kojuto/internal/types"
)

const (
	evtConnect = 1
	evtSendto  = 2
	evtExecve  = 3
	evtOpenat  = 4
	evtRename  = 5
)

// EBPFProbe monitors syscalls using eBPF kprobes.
type EBPFProbe struct {
	objs        *probeObjects
	links       []link.Link
	reader      *perf.Reader
	fileReader  *perf.Reader
	events      chan types.SyscallEvent
	done        chan struct{}
	closeOnce   sync.Once
	LostSamples uint64
}

// NewEBPF creates a new eBPF-based probe.
func NewEBPF() *EBPFProbe {
	return &EBPFProbe{
		events: make(chan types.SyscallEvent, 256),
		done:   make(chan struct{}),
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
		{"do_execveat_common", objs.KprobeExecve},
		{"do_sys_openat2", objs.KprobeOpenat},
		{"vfs_rename", objs.KprobeRename},
	} {
		if kp, kpErr := link.Kprobe(attach.sym, attach.prog, nil); kpErr == nil {
			p.links = append(p.links, kp)
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

	go p.readNetworkLoop()
	go p.readFileLoop()
	return nil
}

func (p *EBPFProbe) readNetworkLoop() {
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
		}
	}
}

func (p *EBPFProbe) readFileLoop() {
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
		case evtRename:
			evt.Syscall = types.EventRename
			evt.SrcPath = path
			evt.DstPath = path2
		default:
			continue
		}

		select {
		case p.events <- evt:
		case <-p.done:
			return
		}
	}
}

func (p *EBPFProbe) Events() <-chan types.SyscallEvent {
	return p.events
}

func (p *EBPFProbe) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.reader != nil {
			p.reader.Close()
		}
		if p.fileReader != nil {
			p.fileReader.Close()
		}
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
