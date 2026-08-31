"""_probe_bri25 —— group B 的块边界 + 扇区空隙调查。

1. 用基名序列重现定位 group B（记录 1539..2048）的 6 个块边界
2. 列出「有记录扇区」之间的空隙，判断是否存在非记录数据（如索引表）
"""
import re

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records
PAT = re.compile(r"[a-z]_[a-z]{3}_[A-Za-z0-9]+_\d{3,4}_\d+")


def base_key(r):
    for v in r.voice_ids(br.data):
        m = PAT.search(v)
        if m:
            p = m.group(0).split("_")
            return "_".join(p[:-2])
    return None


keys = [base_key(r) for r in recs]
idxs = [i for i, k in enumerate(keys) if k]
seq = [keys[i] for i in idxs]

# ---- group B 模板：kana 第二段（记录 1539..1625）----
tmpl = [k for k in keys[1539:1626] if k]
print("group B 模板长度", len(tmpl), "首项", tmpl[0])
t0 = tmpl[0]
hits = []
for j, k in enumerate(seq):
    if k != t0 or idxs[j] < 1539:
        continue
    m = 0
    while m < len(tmpl) and j + m < len(seq) and seq[j + m] == tmpl[m]:
        m += 1
    hits.append((idxs[j], m))
print("\ngroup B 模板首项重现：")
for r0, m in hits:
    print(f"  rec#{r0:5d} 扇区 {recs[r0].sector:5d} {recs[r0].script_class():>5} 匹配 {m}/{len(tmpl)}")

# ---- 空隙 ----
sec = sorted({r.sector for r in recs})
print(f"\n有记录扇区 {len(sec)}  范围 {sec[0]}..{sec[-1]}")
gaps = []
for a, b in zip(sec, sec[1:]):
    if b - a > 1:
        gaps.append((a + 1, b - 1))
print(f"\n空隙 {len(gaps)} 处（>0 扇区）：")
for a, b in gaps:
    print(f"  扇区 {a}..{b}  ({b - a + 1} 个)")

print("\n=== 空隙扇区前 32 字节（解密后）===")
for a, b in gaps:
    for s in range(a, min(b + 1, a + 3)):
        off = s * SECTOR
        print(f"  s{s:5d} {bytes(br.data[off:off+32]).hex(' ')}")
    if b - a >= 3:
        print("  ...")
