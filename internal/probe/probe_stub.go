//go:build linux && !ebpf_generated

package probe

// This file provides stub types for development.
// When eBPF code is generated via `go generate`, build with -tags ebpf_generated
// to use the real implementation instead.

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type probeConnectEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Family      uint16
	Dport       uint16
	Daddr       [16]uint8
	Comm        [16]int8
}

type probeObjects struct {
	KprobeConnect *ebpf.Program `ebpf:"kprobe_connect"`
	Events        *ebpf.Map     `ebpf:"events"`
	TargetPidns   *ebpf.Map     `ebpf:"target_pidns"`
}

func loadProbeObjects(obj *probeObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF objects not generated: run 'make generate' on Linux with clang")
}

func (o *probeObjects) Close() error {
	if o.KprobeConnect != nil {
		o.KprobeConnect.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	if o.TargetPidns != nil {
		o.TargetPidns.Close()
	}
	return nil
}

// Ensure perf import is used (referenced in probe.go)
var _ *perf.Reader
