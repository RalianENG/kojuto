/**
 * Audit hook for Node.js.
 *
 * Staged into the sandbox under a random name and loaded via
 * NODE_OPTIONS="--require <path>" so it executes before any user code.
 * Monkey-patches eval, Function, and vm to log dynamic code execution to
 * stderr in the same format as the Python hook.
 *
 * Output format (one line per event, atomic write), where PREFIX is
 * substituted per scan when the file is staged:
 *     PREFIX eval:<truncated_source>
 *     PREFIX Function:<truncated_body>
 *     PREFIX vm.runInNewContext:<truncated_source>
 *     PREFIX vm.runInThisContext:<truncated_source>
 *     PREFIX vm.Script:<truncated_source>
 *
 * The replacement functions carry the names of the functions they wrap,
 * so `eval.name` and the like read the same as in an unhooked process.
 */

'use strict';

const PREFIX = '__AUDIT_PREFIX__';
const MAX_SNIPPET = 200;

function truncate(s) {
  s = String(s).replace(/\n/g, '\\n').replace(/\r/g, '\\r');
  if (s.length > MAX_SNIPPET) {
    return s.slice(0, MAX_SNIPPET) + '...';
  }
  return s;
}

// nameAs gives a replacement the name of the function it wraps. A
// declared name cannot do it: `function eval` is a syntax error in strict
// mode.
function nameAs(name, fn) {
  Object.defineProperty(fn, 'name', { value: name });
  return fn;
}

function emit(event, snippet) {
  try {
    process.stderr.write(PREFIX + event + ':' + truncate(snippet) + '\n');
  } catch (_) {
    // never break the traced process
  }
}

// --- Patch eval ---
// eval is a global function, not a property of an object we can easily wrap.
// However, indirect eval (e.g. (0,eval)(code)) calls the real eval.
// We intercept direct eval by redefining it on globalThis.
const _origEval = globalThis.eval;
globalThis.eval = nameAs('eval', function (code) {
  emit('eval', code);
  return _origEval.call(this, code);
});

// --- Patch Function constructor ---
const _OrigFunction = Function;
const _hookedFunction = nameAs('Function', function (...args) {
  const body = args.length > 0 ? args[args.length - 1] : '';
  emit('Function', body);
  return new _OrigFunction(...args);
});
_hookedFunction.prototype = _OrigFunction.prototype;
try {
  globalThis.Function = _hookedFunction;
} catch (_) {
  // strict environments may prevent this
}

// --- Patch vm module ---
try {
  const vm = require('vm');

  const _runInNewContext = vm.runInNewContext;
  vm.runInNewContext = nameAs('runInNewContext', function (code, ...rest) {
    emit('vm.runInNewContext', code);
    return _runInNewContext.call(this, code, ...rest);
  });

  const _runInThisContext = vm.runInThisContext;
  vm.runInThisContext = nameAs('runInThisContext', function (code, ...rest) {
    emit('vm.runInThisContext', code);
    return _runInThisContext.call(this, code, ...rest);
  });

  const _Script = vm.Script;
  vm.Script = nameAs('Script', function (code, ...rest) {
    emit('vm.Script', code);
    return new _Script(code, ...rest);
  });
  vm.Script.prototype = _Script.prototype;
} catch (_) {
  // vm module may not be available in all contexts
}
