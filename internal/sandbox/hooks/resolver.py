"""Synthetic DNS resolver for the install/import sandbox.

The sandbox runs with --network=none, so name resolution can never
succeed against a real nameserver. That made hostname-based
exfiltration systematically invisible: the only syscall the tracer saw was
glibc's connect() to the unreachable resolver, which the analyzer
classifies LOW (dns_lookup) on the stated reasoning that "the real C2
signal is the follow-up connect to the resolved IP" — a connect that
could never happen, because the lookup never returned an address. A
package POSTing stolen data to a HOSTNAME therefore scanned clean,
while the same package using an IP literal was caught as
c2_communication.

This resolver closes that gap by answering every A query out of
203.0.113.0/24 (RFC 5737 TEST-NET-3: reserved for documentation, never
routable, never allocated). The caller then proceeds to its connect(),
the sandbox has no route so not a single packet leaves the host, and
strace records the connect the analyzer needs. Nothing here relaxes
containment: the answer is deliberately an address that cannot exist.

The name -> address mapping is deterministic (first byte of the SHA-256
of the queried name, folded into .1-.254) so the analyzer can attribute
a connect back to the hostname that produced it WITHOUT parsing DNS
responses — strace does not trace recvfrom, and node resolves on a
libuv threadpool thread, so PID correlation alone would lose the chain.

AAAA queries are answered NOERROR/NODATA so getaddrinfo() falls back to
the IPv4 answer instead of stalling on a missing AAAA response; that
keeps a single synthetic address family in play.

Binds 127.0.0.53:53 — the systemd-resolved stub address — so
/etc/resolv.conf inside the sandbox reads like an ordinary Ubuntu host
instead of advertising "you are being analyzed".
"""

import hashlib
import os
import socket
import struct
import sys

LISTEN_ADDR = "127.0.0.53"
LISTEN_PORT = 53

# RFC 5737 TEST-NET-3. Must stay in sync with syntheticAddrPrefix in
# internal/analyzer/flowstate.go, which recomputes this mapping to
# attribute a connect back to the queried hostname.
ANSWER_PREFIX = "203.0.113."
ANSWER_TTL = 30

QTYPE_A = 1
QTYPE_AAAA = 28
CLASS_IN = 1

# The readiness marker path arrives as argv[1]. It is written once the
# socket is bound so the launcher can wait for it instead of racing the
# first resolution, and like this file's own name it is random per scan.
READY_PATH = sys.argv[1] if len(sys.argv) > 1 else ""


def synthetic_addr(name):
    """Map a queried name to its synthetic address, deterministically."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return ANSWER_PREFIX + str(1 + digest[0] % 254)


def parse_question(data):
    """Return (name, qtype, qclass, offset-past-question).

    Raises ValueError on anything that is not a plain uncompressed
    question section, which is all glibc, musl, c-ares and Node emit.
    """
    labels = []
    off = 12
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0:
            raise ValueError("compressed name in question")
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    if off + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    return ".".join(labels), qtype, qclass, off + 4


def build_response(data):
    """Build a reply for one query packet, or None if it is not one."""
    if len(data) < 12:
        return None
    flags, qdcount = struct.unpack("!HH", data[2:6])
    if qdcount != 1 or flags & 0x8000:  # not a single-question query
        return None
    name, qtype, qclass, end = parse_question(data)
    question = data[12:end]

    answer = b""
    ancount = 0
    if qclass == CLASS_IN and qtype == QTYPE_A and name:
        # 0xC0 0x0C = pointer to the question name at offset 12.
        answer = (b"\xc0\x0c"
                  + struct.pack("!HHIH", QTYPE_A, CLASS_IN, ANSWER_TTL, 4)
                  + socket.inet_aton(synthetic_addr(name.lower().rstrip("."))))
        ancount = 1
    # Everything else (AAAA, TXT, SRV, ...) gets NOERROR with no answer
    # record: a real resolver's response for a name that exists but has
    # no record of that type.
    header = struct.pack("!HHHHH", 0x8180, 1, ancount, 0, 0)
    return data[:2] + header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))

    if READY_PATH:
        tmp = READY_PATH + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(str(os.getpid()))
        os.rename(tmp, READY_PATH)  # atomic: never appears half-written

    while True:
        try:
            data, peer = sock.recvfrom(2048)
            reply = build_response(data)
            if reply is not None:
                sock.sendto(reply, peer)
        except Exception:
            # A malformed or hostile packet must never take the resolver
            # down: losing it mid-scan would silently restore the
            # false-negative this file exists to remove.
            continue


if __name__ == "__main__":
    main()
