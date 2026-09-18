"""_probe_bri36 —— 对每个扇区**穷举全部 keystream 偏移**，求真实偏移 d。

相比 _probe_bri34 的改进：不再假设扇区首字节是字符边界（扇区常从
多字节字符中间开始）。改用**非法字节**判据，对全部 d 并行筛选：

  p = ks[d : d+W] XOR c        （W=32）
  合法  <=>  不存在 lead(C2..F4) 后面不跟续字节(80..BF)
        且   不存在 F5..FF / C0 / C1

这是一个必要条件，随机 d 的通过率约 (1 - 0.19*0.75)^W ≈ 极低，
因此能通过的就是真偏移。
"""
import sys

import numpy as np

from pwsf_crypto import MT19937, name_hash, XOR_CONST
from pwsf_briefing import SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
raw = np.frombuffer(open(DAT, "rb").read(), dtype=np.uint8)
nsec = len(raw) // SECTOR
key = name_hash("0076531d")

mt = MT19937(key)
mt.advance(20)
KS = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range((nsec + 16) * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8)

W = 32
N = len(KS) - W


def solve(c: np.ndarray) -> np.ndarray:
    p = np.empty((N, W), dtype=np.uint8)
    for i in range(W):
        p[:, i] = KS[i:N + i] ^ c[i]
    lead = (p >= 0xC2) & (p <= 0xF4)
    cont = (p >= 0x80) & (p <= 0xBF)
    bad = (p >= 0xF5) | (p == 0xC0) | (p == 0xC1)
    ok = (bad.sum(axis=1) == 0) & ((lead[:, :-1] & ~cont[:, 1:]).sum(axis=1) == 0)
    return np.flatnonzero(ok)


a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 12
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 20
print(f"扇区 {a0}..{a1}：满足前 {W} 字节无 UTF-8 结构错误的 keystream 偏移")
for s in range(a0, min(a1 + 1, nsec)):
    c = raw[s * SECTOR:s * SECTOR + W]
    ds = solve(c)
    tag = ""
    if len(ds):
        tag = "  d=" + ",".join(str(int(d)) for d in ds[:8])
        tag += f"   块首扇区=" + ",".join(
            f"{(s * SECTOR - int(d)) / SECTOR:g}" for d in ds[:8])
    print(f"s{s:5d}  候选 {len(ds):3d}{tag}")
