#!/bin/bash
# Grant capabilities to the kojuto binary so eBPF mode works without sudo.
# Run once after building:
#   sudo ./scripts/setup-caps.sh ./kojuto
#
# After this, eBPF mode works as a normal user:
#   ./kojuto scan requests --probe-method ebpf

set -euo pipefail

BINARY="${1:-./kojuto}"

if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found: $BINARY"
    echo "Usage: sudo $0 <path-to-kojuto>"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (sudo)"
    exit 1
fi

# CAP_BPF:     load and interact with eBPF programs
# CAP_PERFMON: attach kprobes and read perf events
setcap cap_bpf,cap_perfmon+ep "$BINARY"

echo "Capabilities set on $BINARY:"
getcap "$BINARY"
echo ""
echo "eBPF mode now works without sudo:"
echo "  $BINARY scan <package> --probe-method ebpf"