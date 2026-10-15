import hashlib, os
# 目标：验证"写出"的算法 token 落盘后是否为正确字节
TOKEN = "sha256"
h = hashlib.sha256(b"a").hexdigest()
_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_probe_out.txt")
with open(_out, "w") as f:
    f.write(h + "\n")
    f.write(TOKEN + "\n")
    f.write(hashlib.sha256(b"a").hexdigest() + "\n")
