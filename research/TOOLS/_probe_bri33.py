"""_probe_bri33 —— 对给定扇区，在每个候选 k 下做**完整记录解析**并比较。

判据链（与 pwsf_briefing.parse_record 完全一致）：
  记录头魔数 + 0xFFFFFFFF + 严格递增偏移表 + 文本池可解码
  + 脚本入口 opcode ∈ {0x8d, 0x8e}

只有真正正确的 k 才能同时解出多条自洽的记录。
"""
import sys

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
KMAX = 5
KS = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range(KMAX * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8)

a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 13
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 18

print(f"扇区 {a0}..{a1}，k=0..{KMAX-1} 下的完整记录解析结果")
for s in range(a0, a1 + 1):
    seg = raw[s * SECTOR:(s + 1) * SECTOR]
    print(f"\n--- 扇区 {s} ---")
    for k in range(KMAX):
        buf = bytes(np.frombuffer(seg, dtype=np.uint8) ^ KS[k * SECTOR:(k + 1) * SECTOR])
        recs = []
        for o in range(0, SECTOR - 28, 16):
            if buf[o:o + 4] != b"\x6f\x45\x62\x4e":
                continue
            r = parse_record(buf, o)
            if r is not None:
                recs.append(r)
        tag = "  <== 有记录" if recs else ""
        print(f"  k={k}: {len(recs):2d} 条" + tag)
        for r in recs[:4]:
            t = (r.lines[0] or "")[:34].replace("\n", "\\n")
            print(f"        o={r.off:#06x} 行数={r.n_lines:3d}  {t}")
