#!/usr/bin/env python3
"""Egress probe for the runner netns. Each argument is tcp:<host>:<port> or dns:<name>.
Prints one JSON line per check and always exits 0."""
import json
import socket
import sys


def probe(check):
    kind, _, rest = check.partition(":")
    try:
        if kind == "tcp":
            host, _, port = rest.rpartition(":")
            with socket.create_connection((host, int(port)), timeout=2):
                pass
        elif kind == "dns":
            socket.setdefaulttimeout(2)
            socket.getaddrinfo(rest, None)
        else:
            return {"check": check, "ok": False, "error": "unknown_check"}
        return {"check": check, "ok": True}
    except socket.timeout:
        return {"check": check, "ok": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"check": check, "ok": False, "error": "refused"}
    except socket.gaierror as e:
        return {"check": check, "ok": False, "error": "dns:" + str(e.errno)}
    except (OSError, ValueError) as e:
        return {"check": check, "ok": False, "error": type(e).__name__ + ":" + str(getattr(e, "errno", "") or e)}


def main(argv):
    for check in argv:
        print(json.dumps(probe(check), separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
