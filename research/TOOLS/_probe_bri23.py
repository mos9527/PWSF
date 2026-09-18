"""_probe_bri23 —— 用基名序列的「重现位置」定位语言块的边界与周期。

对 kana 第一段（记录 0..247）的基名序列做模板，在全文件里找该模板的
所有重现起点；若语言按连续块存放，重现起点应等距。
"""
import collections
import re

from pwsf_briefing import load

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

# 有键的记录序号
idxs = [i for i, k in enumerate(keys) if k]
print("有键记录", len(idxs))

# 以 kana 第一段（记录 0..247）为模板
tmpl = [k for k in keys[:248] if k]
print("模板长度", len(tmpl), "首项", tmpl[0], "末项", tmpl[-1])

# 全文件基名序列（只取有键的）
seq = [keys[i] for i in idxs]
print("全文件有键序列长度", len(seq))

# 找模板首项在全序列中的每次出现，并检查后续是否匹配模板
t0 = tmpl[0]
hits = []
for j, k in enumerate(seq):
    if k != t0:
        continue
    m = 0
    while m < len(tmpl) and j + m < len(seq) and seq[j + m] == tmpl[m]:
        m += 1
    hits.append((j, m))
print(f"\n模板首项出现 {len(hits)} 次；各次匹配长度：")
for j, m in hits:
    print(f"  seq#{j:5d} -> rec#{idxs[j]:5d} 扇区 {recs[idxs[j]].sector:5d} "
          f"{recs[idxs[j]].script_class():>5}  匹配 {m}/{len(tmpl)}")

# 记录序号差
print("\n相邻重现的记录序号差：")
for a, b in zip(hits, hits[1:]):
    print(f"  rec {idxs[a[0]]:5d} -> {idxs[b[0]]:5d}   Δ={idxs[b[0]]-idxs[a[0]]:5d}")
