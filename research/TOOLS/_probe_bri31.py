"""_probe_bri31 —— 用已知明文（记录头 8 字节）反解每个记录的 keystream 偏移。

记录头前 8 字节固定为：
    +0  u32 魔数 6f 45 62 4e
    +4  u32 0xFFFFFFFF   （u32 数组的终止符）

对文件内每个 16 字节对齐的偏移 R，令
    t8 = enc[R:R+8] XOR known8
在 keystream 中搜 t8 出现的每个偏移 d，则该记录所在加密块的起点
    P = R - d
（d 即 R 相对块首的字节偏移，也就是 keystream 偏移）

实测：P 全部落在扇区边界上（P % 4096 == 0），说明**加密块按扇区对齐**，
块内 keystream 连续，块长 = 若干扇区。
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
print(f"文件 {len(enc)} 字节 / {nsec} 扇区   keystream {len(KS)} 字节")

DMAX = len(KS) - 8                  # 允许的最大块内偏移
w = np.zeros(DMAX, dtype=np.uint64)
for j in range(8):
    w |= KS[j:DMAX + j].astype(np.uint64) << (8 * j)
order = np.argsort(w, kind="stable")
ws = w[order]

known = np.frombuffer(b"\x6f\x45\x62\x4e\xff\xff\xff\xff", dtype=np.uint8)
KNOWN64 = 0
for j in range(8):
    KNOWN64 |= int(known[j]) << (8 * j)

e = enc.astype(np.uint64)
t = np.zeros(len(enc) - 8, dtype=np.uint64)
for j in range(8):
    t |= e[j:len(enc) - 8 + j] << (8 * j)
t = t[::16] ^ np.uint64(KNOWN64)

lo = np.searchsorted(ws, t, side="left")
hi = np.searchsorted(ws, t, side="right")
hit = np.flatnonzero(hi > lo)
print(f"16 字节对齐候选 {len(t)} 个，命中 {len(hit)} 个")

pages = collections.defaultdict(list)
multi = 0
for i in hit:
    R = int(i) * 16
    ds = [int(x) for x in order[lo[i]:hi[i]]]
    if len(ds) > 1:
        multi += 1
    for d in ds:
        pages[R - d].append(R)
print(f"其中 {multi} 个位置有多个候选 d")

aligned = {P: v for P, v in pages.items() if P % SECTOR == 0}
print(f"\n块起点 P 共 {len(pages)} 个，其中扇区对齐的 {len(aligned)} 个")
print(f"非对齐的 {len(pages) - len(aligned)} 个（应为随机碰撞）")

min_hits = int(sys.argv[1]) if len(sys.argv) > 1 else 2
sel = {P: sorted(v) for P, v in aligned.items() if len(v) >= min_hits}
print(f"\n命中 >= {min_hits} 条记录的块：{len(sel)} 个")
print(f"{'块首扇区':>8} {'P':>12} {'记录数':>6}  首R / 末R")
for P in sorted(sel):
    v = sel[P]
    print(f"{P // SECTOR:8d} {P:#012x} {len(v):6d}  {v[0]:#010x} .. {v[-1]:#010x}")

# 覆盖情况
allR = sorted(R for v in sel.values() for R in v)
print(f"\n这些块共覆盖 {len(allR)} 条记录")
