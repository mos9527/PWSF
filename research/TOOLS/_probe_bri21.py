"""_probe_bri21 —— 全部 2049 条记录的 script_class 游程编码（RLE）。

目的：看清 kana / latin 在文件内的排列结构。
"""
from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records

runs = []
cur = [recs[0].script_class(), recs[0].sector, recs[0].sector, 1]
for r in recs[1:]:
    if r.script_class() == cur[0]:
        cur[2] = r.sector
        cur[3] += 1
    else:
        runs.append(cur)
        cur = [r.script_class(), r.sector, r.sector, 1]
runs.append(cur)

print(f"总游程 {len(runs)}")
for i, (c, s0, s1, n) in enumerate(runs):
    print(f"[{i:3d}] {c:>5}  n={n:4d}  扇区 {s0:4d}..{s1:4d}")
