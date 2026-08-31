"""_probe_bri32 —— 列出「已知明文命中」的 (记录偏移 R, keystream 偏移 d)。

d = R - P。若某扇区内所有命中都满足 d == R % 4096，则该扇区是**独立
加密块**（k=0）。本脚本把每个命中的 d 与其「扇区内偏移」对比，直接暴露
哪些扇区不是独立块。
"""
import collections
import sys

import numpy as np

from pwsf_crypto import MT19937, name_hash, XOR_CONST
from pwsf_briefing import SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
enc = np.frombuffer(open(DAT, "rb").read(), dtype=np.uint8)
nsec = len(enc) // SECTOR
key = name_hash("0076531d")

mt = MT19937(key)
mt.advance(20)
KS = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range((nsec + 8) * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8)

DMAX = len(KS) - 8
w = np.zeros(DMAX, dtype=np.uint64)
for j in range(8):
    w |= KS[j:DMAX + j].astype(np.uint64) << (8 * j)
order = np.argsort(w, kind="stable")
ws = w[order]

KNOWN64 = int.from_bytes(b"\x6f\x45\x62\x4e\xff\xff\xff\xff", "little")
e = enc.astype(np.uint64)
t = np.zeros(len(enc) - 8, dtype=np.uint64)
for j in range(8):
    t |= e[j:len(enc) - 8 + j] << (8 * j)
t = t[::16] ^ np.uint64(KNOWN64)
lo = np.searchsorted(ws, t, side="left")
hi = np.searchsorted(ws, t, side="right")
hit = np.flatnonzero(hi > lo)

hits = []
for i in hit:
    R = int(i) * 16
    for x in order[lo[i]:hi[i]]:
        hits.append((R, int(x)))
hits.sort()

a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 13
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 18
if a1 > 0:
    print(f"扇区 {a0}..{a1} 的命中明细")
    print("  扇区     R        扇区内偏移    d(keystream)   d-扇区内偏移   块首扇区")
    for R, d in hits:
        s = R // SECTOR
        if not (a0 <= s <= a1):
            continue
        o = R % SECTOR
        print(f"{s:6d} {R:#010x} {o:8d} {d:12d} {d - o:12d} "
              f"{(R - d) / SECTOR:12.3f}")
    print()

# 全文件汇总：d - (R % 4096) 的分布
diff = collections.Counter()
for R, d in hits:
    diff[d - (R % SECTOR)] += 1
print("全文件 (d - 扇区内偏移) 的分布：", dict(sorted(diff.items())[:20]))
print(f"总命中 {len(hits)}")
