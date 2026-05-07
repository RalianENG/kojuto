"""Site-wide customization hook.

Standard Python mechanism (PEP 578) for runtime event auditing.
Loaded automatically by the interpreter on startup.
"""

import os
import sys

_MAX = 200
_FRAMES = 8
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
    s = str(s).replace("\n", "\\n").replace("\r", "\\r")
    if len(s) > _MAX:
        return s[:_MAX] + "..."
    return s


def _w(tag, body):
    sys.stderr.write(_P + tag + ":" + body + "\n")
    sys.stderr.flush()


def _origin(fallback):
    """Walk the Python call stack and return the .py file responsible
    for the compile/exec call.

    Returns "+<path>" when the deepest user-code frame is found — the
    leading "+" tells the Go analyzer this event originates in audited
    code and must NOT be filtered by the path-based benign list. When
    no user frame appears, returns the deepest non-internal frame so
    the existing benign filter (stdlib/site-packages substring match)
    still works for compat-library noise.
    """
    try:
        f = sys._getframe(2)  # skip _origin + _h
    except ValueError:
        return fallback
    me = __file__
    seen = 0
    deepest = ""
    while f is not None and seen < _FRAMES:
        fn = f.f_code.co_filename
        if fn != me:
            if _is_user(fn):
                return "+" + fn
            if not deepest:
                deepest = fn
            seen += 1
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
