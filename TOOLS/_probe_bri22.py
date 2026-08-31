"""_probe_bri22 —— 用「语音 ID 基名序列」找语言的重复周期。

思路：同一会话在不同语言下的语音资源名相同（语音是共用的），
所以把每条记录的首个语音 ID 去掉「行号/变体」得到基名，按文件顺序
排成序列；若语言是连续块，则该序列会呈**周期性重复**。
"""
import collections
import re
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records

PAT = re.compile(r"[a-z]_[a-z]{3}_[A-Za-z0-9]+_\d{3,4}_\d+")


def base_key(r):
    """取本记录首个语音 ID 的基名（去掉行号与变体）。"""
    for v in r.voice_ids(br.data):
        m = PAT.search(v)
        if m:
            s = m.group(0)
            parts = s.split("_")
            return "_".join(parts[:-2])
    return None


keys = [base_key(r) for r in recs]
print("有基名的记录:", sum(1 for k in keys if k), "/", len(recs))

# 打印前 400 条序列（压缩：连续相同基名合并）
seq = []
for i, k in enumerate(keys):
    seq.append((i, k))
print("\n=== 前 400 条：序号 扇区 类别 基名 ===")
for i, k in seq[:400]:
    r = recs[i]
    print(f"{i:5d} {r.sector:5d} {r.script_class():>5} {k}")

# 基名首次出现次序 -> 检测周期
print("\n=== 基名首次出现的记录序号（前 60 个不同基名）===")
seen = {}
firsts = []
for i, k in enumerate(keys):
    if k and k not in seen:
        seen[k] = i
        firsts.append((i, k))
for i, k in firsts[:60]:
    print(f"  {i:5d} {k}")
print("不同基名总数:", len(firsts))
