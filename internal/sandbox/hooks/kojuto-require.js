/**
 * Kojuto audit hook for Node.js.
 *
 * Loaded via NODE_OPTIONS="--require /opt/kojuto/kojuto-require.js" so it
 * executes before any user code.  Monkey-patches eval, Function, and vm
 * to log dynamic code execution to stderr in the same format as the
 * Python hook.
 *
 * Output format (one line per event, atomic write):
 *     KOJUTO:eval:<truncated_source>
 *     KOJUTO:Function:<truncated_body>
 *     KOJUTO:vm.runInNewContext:<truncated_source>
 *     KOJUTO:vm.runInThisContext:<truncated_source>
 *     KOJUTO:vm.Script:<truncated_source>
 */

'use strict';

const MAX_SNIPPET = 200;

function truncate(s) {
  s = String(s).replace(/\n/g, '\\n').replace(/\r/g, '\\r');
  if (s.length > MAX_SNIPPET) {
    return s.slice(0, MAX_SNIPPET) + '...';
  }
  return s;
}

function emit(event, snippet) {
  try {
    process.stderr.write('KOJUTO:' + event + ':' + truncate(snippet) + '\n');
  } catch (_) {
    // never break the traced process
  }
}

// --- Patch eval ---
// eval is a global function, not a property of an object we can easily wrap.
// However, indirect eval (e.g. (0,eval)(code)) calls the real eval.
// We intercept direct eval by redefining it on globalThis.
const _origEval = globalThis.eval;
globalThis.eval = function kojutoEval(code) {
  emit('eval', code);
  return _origEval.call(this, code);
};

// --- Patch Function constructor ---
const _OrigFunction = Function;
const _KojutoFunction = function KojutoFunction(...args) {
  const body = args.length > 0 ? args[args.length - 1] : '';
  emit('Function', body);
  return new _OrigFunction(...args);
};
_KojutoFunction.prototype = _OrigFunction.prototype;
try {
  globalThis.Function = _KojutoFunction;
} catch (_) {
  // strict environments may prevent this
}

// --- Patch vm module ---
try {
  const vm = require('vm');

  const _runInNewContext = vm.runInNewContext;
  vm.runInNewContext = function kojutoRunInNewContext(code, ...rest) {
    emit('vm.runInNewContext', code);
    return _runInNewContext.call(this, code, ...rest);
  };

  const _runInThisContext = vm.runInThisContext;
  vm.runInThisContext = function kojutoRunInThisContext(code, ...rest) {
    emit('vm.runInThisContext', code);
    return _runInThisContext.call(this, code, ...rest);
  };

  const _Script = vm.Script;
  vm.Script = function KojutoScript(code, ...rest) {
    emit('vm.Script', code);
    return new _Script(code, ...rest);
  };
  vm.Script.prototype = _Script.prototype;
} catch (_) {
  // vm module may not be available in all contexts
}
