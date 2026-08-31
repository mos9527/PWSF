"""_probe_bri24 —— 打印 6 个候选语言块各自的样例台词（客观事实）。

块边界来自 _probe_bri23.py：基名序列 v_bri_kaz0010 的重现位置
rec 0 / 248 / 518 / 776 / 1030 / 1281（group A）
以及第二段 kana 的起点 rec 1539（group B）。
本脚本只负责把每块的样例文本打出来，供语言识别与文档取证。
"""
import re
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records

BOUNDS = [0, 248, 518, 776, 1030, 1281, 1539,
          1626, 1710, 1794, 1878, 1962, 2049]

n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
for bi in range(len(BOUNDS) - 1):
    a, b = BOUNDS[bi], BOUNDS[bi + 1]
    blk = recs[a:b]
    print(f"\n===== 块 {bi}: 记录 {a}..{b-1}  ({len(blk)} 条)  "
          f"扇区 {blk[0].sector}..{blk[-1].sector} =====")
    for r in blk[:n]:
        t = (r.lines[0] or "").replace("\n", "\\n")[:90]
        print(f"  #{a + blk.index(r):5d} s{r.sector:4d} {t}")
