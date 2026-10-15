import json, sys, hashlib, os

def hx(s):
    return s.encode('utf-8').hex()

def show(path):
    print("="*70)
    print("FILE:", path)
    if not os.path.exists(path):
        print("  MISSING"); return
    raw = open(path, 'rb').read()
    print("  size_bytes =", len(raw))
    try:
        d = json.loads(raw.decode('utf-8'))
    except Exception as e:
        print("  JSON PARSE FAIL:", e); return
    if isinstance(d, dict):
        print("  TOP-LEVEL type=dict, n_keys =", len(d))
        for k in d.keys():
            print("    key hex =", hx(k), " len=", len(k))
    skills = d.get('skills') if isinstance(d, dict) else None
    if isinstance(skills, list):
        print("  skills len =", len(skills))
        keyset = set()
        for e in skills:
            if isinstance(e, dict):
                keyset |= set(e.keys())
        print("  entry key union hex =", [hx(k) for k in sorted(keyset)])
        for i, e in enumerate(skills[:8]):
            if not isinstance(e, dict):
                print("    [%d] NOT DICT" % i); continue
            nm = e.get('name','')
            ty = e.get('type','')
            de = e.get('description', None)
            ur = e.get('url','')
            dg = e.get('digest','')
            print("    [%d] name_hex=%s type_hex=%s desc_present=%s desc_len=%s url=%s" % (
                i, hx(nm), hx(ty), de is not None, (len(de) if isinstance(de,str) else None), ur))
            if isinstance(dg, str):
                print("         digest_hex =", hx(dg))
    else:
        print("  skills not a list:", type(skills))

for p in sys.argv[1:]:
    show(p)
