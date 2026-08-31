"""_probe_bri37 —— 全文件 × k=0..7 的完整记录解析，统计新增记录。

对 1011 个扇区、每个 k，用 pwsf_briefing.parse_record 解析记录，
统计「只在 k>0 下才解出的记录」，评估 k=0 模型的覆盖率。
"""
import collections

import numpy as np

from pwsf_crypto import MT19937, name_hash, XOR_CONST
from pwsf_briefing import SECTOR, parse_record

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
raw = open(DAT, "rb").read()
nsec = len(raw) // SECTOR
key = name_hash("0076531d")

mt = MT19937(key)
mt.advance(20)
KMAX = 8
KS = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range(KMAX * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8)

found = {}          # (sector, k) -> [Record]
for s in range(nsec):
    seg = raw[s * SECTOR:(s + 1) * SECTOR]
    if len(seg) < SECTOR:
        break
    arr = np.frombuffer(seg, dtype=np.uint8)
    for k in range(KMAX):
        buf = bytes(arr ^ KS[k * SECTOR:(k + 1) * SECTOR])
        rs = []
        for o in range(0, SECTOR - 28, 16):
            if buf[o:o + 4] != b"\x6f\x45\x62\x4e":
                continue
            r = parse_record(buf, o)
            if r is not None:
                rs.append(r)
        if rs:
            found[(s, k)] = rs

cnt = collections.Counter(k for (_, k) in found)
print("各 k 下解出记录的扇区数：", dict(sorted(cnt.items())))
tot = collections.Counter()
for (s, k), rs in found.items():
    tot[k] += len(rs)
print("各 k 下的记录条数：", dict(sorted(tot.items())))

only = {s: (k, rs) for (s, k), rs in
        sorted(((s, k, rs) for (s, k), rs in found.items() if k > 0))
        if s not in found or s not in [ss for (ss, kk) in found if kk == 0]}
print(f"\n只在 k>0 下解出记录的扇区：{len(only)} 个")
for s, (k, rs) in sorted(only.items())[:40]:
    t = (rs[0].lines[0] or "")[:40].replace("\n", "\\n")
    print(f"  s{s:5d} k={k}  {len(rs)} 条   {t}")

new = sum(len(rs) for s, (k, rs) in only.items())
print(f"\n新增记录 {new} 条（k=0 模型遗漏）")
