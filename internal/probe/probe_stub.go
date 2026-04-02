//go:build linux && !ebpf_generated

package probe

// This file provides stub types for development.
// When eBPF code is generated via `go generate`, build with -tags ebpf_generated
// to use the real implementation instead.

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type probeConnectEvent struct {
	TimestampNs uint64
	Pid         uint32
	UID         uint32
	Family      uint16
	Dport       uint16
	Daddr       [16]uint8
	Comm        [16]int8
}

type probeFileEvent struct {
	TimestampNs uint64
	Pid         uint32
	UID         uint32
	EventType   uint8
	Pad         [3]uint8
	Path        [128]int8
	Path2       [128]int8
}

type probeObjects struct {
	KprobeConnect *ebpf.Program `ebpf:"kprobe_connect"`
	KprobeSendto  *ebpf.Program `ebpf:"kprobe_sendto"`
	KprobeSendmsg *ebpf.Program `ebpf:"kprobe_sendmsg"`
	KprobeBind    *ebpf.Program `ebpf:"kprobe_bind"`
	KprobeListen  *ebpf.Program `ebpf:"kprobe_listen"`
	KprobeAccept  *ebpf.Program `ebpf:"kprobe_accept"`
	KprobeExecve  *ebpf.Program `ebpf:"kprobe_execve"`
	KprobeOpenat  *ebpf.Program `ebpf:"kprobe_openat"`
	KprobeRename  *ebpf.Program `ebpf:"kprobe_rename"`
	Events        *ebpf.Map     `ebpf:"events"`
	FileEvents    *ebpf.Map     `ebpf:"file_events"`
	TargetPidns   *ebpf.Map     `ebpf:"target_pidns"`
}

func loadProbeObjects(_ *probeObjects, _ *ebpf.CollectionOptions) error {
	return errors.New("eBPF objects not generated: run 'make generate' on Linux with clang")
}

func (o *probeObjects) Close() error {
	progs := []*ebpf.Program{
		o.KprobeConnect, o.KprobeSendto, o.KprobeSendmsg,
		o.KprobeBind, o.KprobeListen, o.KprobeAccept,
		o.KprobeExecve, o.KprobeOpenat, o.KprobeRename,
	}
	for _, p := range progs {
		if p != nil {
			p.Close()
		}
	}
	maps := []*ebpf.Map{o.Events, o.FileEvents, o.TargetPidns}
	for _, m := range maps {
		if m != nil {
			m.Close()
		}
	}
	return nil
}

// Ensure perf import is used (referenced in probe.go).
var _ *perf.Reader
