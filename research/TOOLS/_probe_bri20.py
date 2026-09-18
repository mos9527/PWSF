"""_probe_bri20 —— 按文件偏移顺序列出记录，看 kana/latin 的排列模式。

若同一会话的多语言版本是**相邻存放**的，会看到周期性模式。
对每条记录打印：
  序号 扇区 idx 类别 台词数 语音ID(首) 首行前 24 字
"""
import re
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records

lim = int(sys.argv[1]) if len(sys.argv) > 1 else 200
print(f"{'#':>5} {'sect':>5} {'idx':>6} {'cls':>5} {'n':>3}  voice / 首行")
for i, r in enumerate(recs[:lim]):
    v = r.voice_ids(br.data)
    v0 = v[0] if v else ""
    t = r.lines[0][:26].replace("\n", "\\n") if r.lines else ""
    print(f"{i:5d} {r.sector:5d} {r.idx:6d} {r.script_class():>5} "
          f"{r.n_lines:3d}  {v0:26s} {t}")
