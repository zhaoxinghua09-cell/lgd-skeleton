import sys, json, hashlib, os

# 构造候选 token，不写任何字面算法名，规避显示层替换
def tok(codes):
    return bytes(codes)
SHA256 = tok([115,104,97,50,53,54])      # 6 chars
HEXLIKE = tok([104,107,109,51,51,51])    # 6 chars, 当前显示层疑似替身

def scan(path):
    b = open(path, 'rb').read()
    print("FILE:", path, "bytes=", len(b))
    for label, key in (("candA", SHA256), ("candB", HEXLIKE)):
        idxs = []
        i = b.find(key)
        while i != -1 and len(idxs) < 3:
            idxs.append(i)
            i = b.find(key, i+1)
        print("  ", label, "count_first3=", idxs)
        for i in idxs[:2]:
            print("      win hex @", i, "=", b[max(0,i-4):i+12].hex())
    # 找形如 <token>':' 的 6 字母前缀候选：打印 digest 附近原始 hex
    # 定位 json 中 "digest" 字段
    dkey = tok([100,105,103,101,115,116])  # digest
    for m in [b.find(dkey)]:
        if m != -1:
            print("  digest field win hex @", m, "=", b[m:m+40].hex())

for p in sys.argv[1:]:
    if os.path.exists(p):
        scan(p)
    else:
        print("MISSING:", p)
