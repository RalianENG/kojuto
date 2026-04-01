//go:build linux

package probe

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type connect_event probe probe.c -- -I../../headers -O2 -g

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/RalianENG/kojuto/internal/types"
)

// EBPFProbe monitors connect(2) syscalls using eBPF kprobes.
type EBPFProbe struct {
	objs        *probeObjects
	link        link.Link
	reader      *perf.Reader
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

	// Set target PID namespace inode
	key := uint32(0)
	if err := objs.TargetPidns.Put(key, targetPIDNS); err != nil {
		return fmt.Errorf("setting target pidns: %w", err)
	}

	// Attach kprobe to __sys_connect
	kp, err := link.Kprobe("__sys_connect", objs.KprobeConnect, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	p.link = kp

	// Open perf event reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*16)
	if err != nil {
		return fmt.Errorf("creating perf reader: %w", err)
	}
	p.reader = rd

	go p.readLoop()
	return nil
}

func (p *EBPFProbe) readLoop() {
	defer close(p.events)

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

		// Convert int8 comm to bytes
		var commBytes [16]byte
		for i, c := range raw.Comm {
			commBytes[i] = byte(c)
		}

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

func (p *EBPFProbe) Events() <-chan types.SyscallEvent {
	return p.events
}

func (p *EBPFProbe) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.reader != nil {
			p.reader.Close()
		}
		if p.link != nil {
			p.link.Close()
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
