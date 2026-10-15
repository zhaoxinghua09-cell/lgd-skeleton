import json, sys, os, hashlib, subprocess

# 本文件位于 <repo>/gates/probes/，向上三级即仓库根
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IDX = os.path.join(_REPO, ".well-known", "agent-skills", "index.json")
base = os.path.dirname(IDX)

raw = open(IDX,'rb').read()
d = json.loads(raw.decode('utf-8'))
print("=== $schema value ===")
sv = d.get('$schema')
print("  repr =", repr(sv))
print("  hex  =", sv.encode().hex() if isinstance(sv,str) else "N/A")
print("  len  =", len(sv) if isinstance(sv,str) else None)
# RFC canonical
rfc = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
print("  matches RFC literal =", sv == rfc)
print("  rfc hex =", rfc.encode().hex())

print("\n=== per-entry digest check (local file) ===")
for e in d['skills']:
    url = e['url']
    # resolve relative to index dir
    local = os.path.normpath(os.path.join(base, url))
    exists = os.path.exists(local)
    calc = None
    if exists:
        calc = "sha256:" + hashlib.sha256(open(local,'rb').read()).hexdigest()
    print("  name=%s" % e['name'])
    print("    url=%s" % url)
    print("    local=%s exists=%s" % (local, exists))
    print("    index digest =", e['digest'])
    print("    calc  digest =", calc)
    print("    MATCH =", (calc == e['digest']) if calc else "NO-FILE")
