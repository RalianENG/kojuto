"""Site-wide customization hook.

Standard Python mechanism (PEP 578) for runtime event auditing.
Loaded automatically by the interpreter on startup.
"""

import sys

_MAX = 200
_P = chr(75) + chr(79) + chr(74) + chr(85) + chr(84) + chr(79) + ":"


def _t(s):
    s = str(s).replace("\n", "\\n").replace("\r", "\\r")
    if len(s) > _MAX:
        return s[:_MAX] + "..."
    return s


def _w(tag, body):
    sys.stderr.write(_P + tag + ":" + body + "\n")
    sys.stderr.flush()


def _h(event, args):
    try:
        if event == "compile":
            source = args[0] if args else ""
            fn = args[1] if len(args) > 1 else ""
            _w("compile", str(fn) + ":" + _t(source))

        elif event == "exec":
            code = args[0] if args else ""
            fn = ""
            if hasattr(code, "co_filename"):
                fn = code.co_filename
            _w("exec", str(fn) + ":" + _t(repr(code)))

        elif event == "import":
            module = args[0] if args else ""
            _w("import", _t(module))

        elif event == "ctypes.dlopen":
            name = args[0] if args else ""
            _w("ctypes.dlopen", _t(name))

    except Exception:
        pass


sys.addaudithook(_h)
