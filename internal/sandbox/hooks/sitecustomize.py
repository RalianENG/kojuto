"""Site-wide customization hook.

Standard Python mechanism (PEP 578) for runtime event auditing.
Loaded automatically by the interpreter on startup.
"""

import os
import sys

_MAX = 200
_P = chr(75) + chr(79) + chr(74) + chr(85) + chr(84) + chr(79) + ":"

# Frames whose co_filename starts with one of these are treated as
# "originated by the scanned package or other user-controllable code".
# A dynamic compile/exec call from such a frame is reported to the
# analyzer; calls from purely stdlib/library frames are suppressed
# (legit compat libs like six exec their own internal source).
_USER_PREFIXES = ["/tmp/", "/install/", "/home/dev/"]

_SITE = "/usr/local/lib/python" + sys.version[:4] + "/site-packages/"
for _name in os.environ.get("KOJUTO_SCAN_PKGS", "").split(","):
    _name = _name.strip()
    if not _name:
        continue
    # Pip distribution name often differs from the import-time module
    # name (PyYAML→yaml, python-dateutil→dateutil). Cover the common
    # transformations so the prefix list still hits the installed dir.
    for _v in {_name, _name.replace("-", "_"), _name.lower(),
               _name.replace("-", "_").lower()}:
        _USER_PREFIXES.append(_SITE + _v + "/")
        _USER_PREFIXES.append(_SITE + _v + ".py")


def _is_user(fn):
    if not fn or fn[:1] == "<":
        return False
    for p in _USER_PREFIXES:
        if fn.startswith(p):
            return True
    return False


def _t(s):
    # Escape every C0 control byte (0x00-0x1f) and DEL (0x7f) to a
    # printable form. The wire format only needs newline-stripping for
    # framing safety (handled in _w too), but the snippet field
    # eventually surfaces in report.json's code_snippet — a downstream
    # consumer that decodes the JSON and prints the raw string (e.g.
    # `jq -r .events[].code_snippet`) used to receive an unescaped
    # ESC (0x1b) byte and let an attacker-supplied payload paint
    # arbitrary text on the user's terminal via ANSI sequences.
    out = []
    for ch in str(s):
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append(ch)
    s = "".join(out)
    if len(s) > _MAX:
        return s[:_MAX] + "..."
    return s


def _w(tag, body):
    # Wire-format invariant: each KOJUTO: emission must occupy exactly
    # one stderr line. The Go parser splits on '\n' and treats every
    # KOJUTO:-prefixed line as an independent event. Strip line and null
    # bytes from `body` so an attacker-controlled co_filename or compile
    # filename arg cannot smuggle a fake follow-up event onto the wire.
    # _t() already escapes newlines in the snippet field, so this is a
    # defense for the filename field (which is concatenated raw from
    # _origin()) and a belt-and-braces guard for any future tag.
    body = body.replace("\n", "").replace("\r", "").replace("\0", "")
    sys.stderr.write(_P + tag + ":" + body + "\n")
    sys.stderr.flush()


def _origin(fallback):
    """Walk the Python call stack and return the .py file responsible
    for the compile/exec call.

    Returns "+<path>" when a user-code frame is found anywhere on the
    stack — the leading "+" tells the Go analyzer this event originates
    in audited code and must NOT be filtered by the path-based benign
    list. When no user frame appears, returns the first non-internal
    frame so the existing benign filter (stdlib/site-packages substring
    match) still works for compat-library noise.

    The walk is unbounded by design: a depth cap would let a malicious
    package bury its own frame under stdlib wrappers and evade the
    user-origin marker. Stack walking is O(depth) on a linked list and
    early-returns on the first user frame, so the practical cost is
    negligible compared with the surrounding compile/exec work.
    """
    try:
        f = sys._getframe(2)  # skip _origin + _h
    except ValueError:
        return fallback
    me = __file__
    deepest = ""
    while f is not None:
        fn = f.f_code.co_filename
        if fn != me:
            if _is_user(fn):
                return "+" + fn
            if not deepest:
                deepest = fn
        f = f.f_back
    if deepest:
        return deepest
    return fallback


def _h(event, args):
    try:
        if event == "compile":
            source = args[0] if args else ""
            fn = str(args[1]) if len(args) > 1 else ""
            _w("compile", _origin(fn) + ":" + _t(source))

        elif event == "exec":
            code = args[0] if args else ""
            fn = ""
            if hasattr(code, "co_filename"):
                fn = code.co_filename
            _w("exec", _origin(fn) + ":" + _t(repr(code)))

        elif event == "import":
            module = args[0] if args else ""
            _w("import", _t(module))

        elif event == "ctypes.dlopen":
            name = args[0] if args else ""
            _w("ctypes.dlopen", _t(name))

    except Exception:
        pass


sys.addaudithook(_h)
